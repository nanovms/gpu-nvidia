/*******************************************************************************
    Copyright (c) 2015-2021 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "uvm_api.h"
#include "uvm_global.h"
#include "uvm_gpu_replayable_faults.h"
#include "uvm_tools_init.h"
#include "uvm_lock.h"
#include "uvm_va_space.h"
#include "uvm_va_range.h"
#include "uvm_va_block.h"
#include "uvm_tools.h"
#include "uvm_common.h"
#include "uvm_linux_ioctl.h"
#include "uvm_hmm.h"
#include "uvm_mem.h"

#define NVIDIA_UVM_DEVICE_NAME          "nvidia-uvm"

static dev_t g_uvm_base_dev;

// List of fault service contexts for CPU faults
static LIST_HEAD(g_cpu_service_block_context_list);

static uvm_spinlock_t g_cpu_service_block_context_list_lock;

NV_STATUS uvm_service_block_context_init(void)
{
    unsigned num_preallocated_contexts = 4;

    uvm_spin_lock_init(&g_cpu_service_block_context_list_lock, UVM_LOCK_ORDER_LEAF);

    // Pre-allocate some fault service contexts for the CPU and add them to the global list
    while (num_preallocated_contexts-- > 0) {
        uvm_service_block_context_t *service_context = uvm_kvmalloc(sizeof(*service_context));
        if (!service_context)
            return NV_ERR_NO_MEMORY;

        list_add(&service_context->cpu_fault.service_context_list, &g_cpu_service_block_context_list);
    }

    return NV_OK;
}

void uvm_service_block_context_exit(void)
{
    uvm_service_block_context_t *service_context, *service_context_tmp;

    // Free fault service contexts for the CPU and add clear the global list
    list_for_each_entry_safe(service_context, service_context_tmp, &g_cpu_service_block_context_list,
                             cpu_fault.service_context_list) {
        uvm_kvfree(service_context);
    }
    INIT_LIST_HEAD(&g_cpu_service_block_context_list);
}

static NV_STATUS uvm_api_initialize(UVM_INITIALIZE_PARAMS *params, uvm_fd filp)
{
    return uvm_va_space_initialize(uvm_va_space_get(filp), params->flags);
}

static NV_STATUS uvm_api_pageable_mem_access(UVM_PAGEABLE_MEM_ACCESS_PARAMS *params, uvm_fd filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    params->pageableMemAccess = uvm_va_space_pageable_mem_access_supported(va_space) ? NV_TRUE : NV_FALSE;
    return NV_OK;
}

closure_func_basic(fdesc_mmap, sysreturn, uvm_mmap,
                   vmap vma, u64 offset)
{
    uvm_fd filp = struct_from_field(closure_self(), uvm_fd, mmap);
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_range_t *va_range;
    NV_STATUS status = uvm_global_get_status();
    sysreturn ret = 0;
    bool vma_wrapper_allocated = false;

    if (status != NV_OK)
        return -nv_status_to_errno(status);

    status = uvm_va_space_initialized(va_space);
    if (status != NV_OK)
        return -EBADFD;

    // UVM mappings are required to set offset == VA. This simplifies things
    // since we don't have to worry about address aliasing (except for fork,
    // handled separately) and it makes unmap_mapping_range simpler.
    if (vma->node.r.start != offset) {
        UVM_DBG_PRINT_RL("vm_start 0x%lx != vm_pgoff 0x%lx\n", vma->node.r.start, offset);
        return -EINVAL;
    }

    // Enforce shared read/writable mappings so we get all fault callbacks
    // without the kernel doing COW behind our backs. The user can still call
    // mprotect to change protections, but that will only hurt user space.
    if ((vma->flags & (VMAP_FLAG_SHARED|VMAP_FLAG_READABLE|VMAP_FLAG_WRITABLE)) !=
                         (VMAP_FLAG_SHARED|VMAP_FLAG_READABLE|VMAP_FLAG_WRITABLE)) {
        UVM_DBG_PRINT_RL("User requested non-shared or non-writable mapping\n");
        return -EINVAL;
    }

    // This identity assignment is needed so uvm_vm_open can find its parent vma
    uvm_vma_wrapper_t *vma_wrapper = uvm_vma_wrapper_alloc(vma);
    if (!vma_wrapper) {
        ret = -ENOMEM;
        goto out;
    }
    vma_wrapper_allocated = true;

    // The kernel has taken mmap_lock in write mode, but that doesn't prevent
    // this va_space from being modified by the GPU fault path or from the ioctl
    // path where we don't have this mm for sure, so we have to lock the VA
    // space directly.
    uvm_va_space_down_write(va_space);

    // uvm_va_range_create_mmap will catch collisions. Below are some example
    // cases which can cause collisions. There may be others.
    // 1) An overlapping range was previously created with an ioctl, for example
    //    for an external mapping.
    // 2) This file was passed to another process via a UNIX domain socket
    status = uvm_va_range_create_mmap(va_space, 0, vma_wrapper, NULL);

    if (status == NV_ERR_UVM_ADDRESS_IN_USE) {
        // If the mmap is for a semaphore pool, the VA range will have been
        // allocated by a previous ioctl, and the mmap just creates the CPU
        // mapping.
        va_range = uvm_va_range_find(va_space, vma->node.r.start);
        if (va_range && va_range->node.start == vma->node.r.start &&
                va_range->node.end + 1 == vma->node.r.end &&
                va_range->type == UVM_VA_RANGE_TYPE_SEMAPHORE_POOL) {
            uvm_vma_wrapper_destroy(vma_wrapper);
            vma_wrapper_allocated = false;
            status = uvm_mem_map_cpu_user(va_range->semaphore_pool.mem, va_range->va_space, vma);
        }
    }

    if (status != NV_OK) {
        UVM_DBG_PRINT_RL("Failed to create or map VA range for vma [0x%lx, 0x%lx): %s\n",
                         vma->node.r.start, vma->node.r.end, nvstatusToString(status));
        ret = -nv_status_to_errno(status);
    }

    uvm_va_space_up_write(va_space);

out:
    if (ret != 0 && vma_wrapper_allocated)
        uvm_vma_wrapper_destroy(vma_wrapper);

    return ret;
}

closure_func_basic(fdesc_ioctl, sysreturn, uvm_ioctl,
                   unsigned long cmd, vlist ap)
{
    uvm_fd filp = struct_from_field(closure_self(), uvm_fd, ioctl);

    switch (cmd)
    {
        case UVM_DEINITIALIZE:
            return 0;

        UVM_ROUTE_CMD_STACK_NO_INIT_CHECK(UVM_INITIALIZE,                  uvm_api_initialize);

        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_PAGEABLE_MEM_ACCESS,            uvm_api_pageable_mem_access);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_PAGEABLE_MEM_ACCESS_ON_GPU,     uvm_api_pageable_mem_access_on_gpu);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_REGISTER_GPU,                   uvm_api_register_gpu);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_UNREGISTER_GPU,                 uvm_api_unregister_gpu);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_CREATE_RANGE_GROUP,             uvm_api_create_range_group);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_DESTROY_RANGE_GROUP,            uvm_api_destroy_range_group);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ENABLE_PEER_ACCESS,             uvm_api_enable_peer_access);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_DISABLE_PEER_ACCESS,            uvm_api_disable_peer_access);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_SET_RANGE_GROUP,                uvm_api_set_range_group);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_CREATE_EXTERNAL_RANGE,          uvm_api_create_external_range);
        UVM_ROUTE_CMD_ALLOC_INIT_CHECK(UVM_MAP_EXTERNAL_ALLOCATION,        uvm_api_map_external_allocation);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_MAP_EXTERNAL_SPARSE,            uvm_api_map_external_sparse);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_FREE,                           uvm_api_free);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_PREVENT_MIGRATION_RANGE_GROUPS, uvm_api_prevent_migration_range_groups);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ALLOW_MIGRATION_RANGE_GROUPS,   uvm_api_allow_migration_range_groups);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_SET_PREFERRED_LOCATION,         uvm_api_set_preferred_location);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_UNSET_PREFERRED_LOCATION,       uvm_api_unset_preferred_location);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_SET_ACCESSED_BY,                uvm_api_set_accessed_by);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_UNSET_ACCESSED_BY,              uvm_api_unset_accessed_by);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_REGISTER_GPU_VASPACE,           uvm_api_register_gpu_va_space);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_UNREGISTER_GPU_VASPACE,         uvm_api_unregister_gpu_va_space);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_REGISTER_CHANNEL,               uvm_api_register_channel);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_UNREGISTER_CHANNEL,             uvm_api_unregister_channel);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ENABLE_READ_DUPLICATION,        uvm_api_enable_read_duplication);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_DISABLE_READ_DUPLICATION,       uvm_api_disable_read_duplication);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_MIGRATE,                        uvm_api_migrate);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ENABLE_SYSTEM_WIDE_ATOMICS,     uvm_api_enable_system_wide_atomics);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_DISABLE_SYSTEM_WIDE_ATOMICS,    uvm_api_disable_system_wide_atomics);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_TOOLS_READ_PROCESS_MEMORY,      uvm_api_tools_read_process_memory);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_TOOLS_WRITE_PROCESS_MEMORY,     uvm_api_tools_write_process_memory);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_TOOLS_GET_PROCESSOR_UUID_TABLE, uvm_api_tools_get_processor_uuid_table);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_MAP_DYNAMIC_PARALLELISM_REGION, uvm_api_map_dynamic_parallelism_region);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_UNMAP_EXTERNAL,                 uvm_api_unmap_external);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_MIGRATE_RANGE_GROUP,            uvm_api_migrate_range_group);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_TOOLS_FLUSH_EVENTS,             uvm_api_tools_flush_events);
        UVM_ROUTE_CMD_ALLOC_INIT_CHECK(UVM_ALLOC_SEMAPHORE_POOL,           uvm_api_alloc_semaphore_pool);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_CLEAN_UP_ZOMBIE_RESOURCES,      uvm_api_clean_up_zombie_resources);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_POPULATE_PAGEABLE,              uvm_api_populate_pageable);
        UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_VALIDATE_VA_RANGE,              uvm_api_validate_va_range);
    }
    return ioctl_generic(&filp->f->f, cmd, ap);
}

closure_func_basic(fdesc_close, sysreturn, uvm_close,
                   context ctx, io_completion completion)
{
    uvm_fd filp = struct_from_field(closure_self(), uvm_fd, close);
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    uvm_va_space_destroy(va_space);
    NV_KFREE(filp, sizeof(*filp));

    return io_complete(completion, 0);
}

closure_function(0, 1, sysreturn, uvm_open,
                 file, f)
{
    uvm_fd fd;
    NV_STATUS status;

    NV_KMALLOC(fd, sizeof(*fd));
    if (!fd)
        return -ENOMEM;
    status = uvm_global_get_status();
    if (status == NV_OK) {
        f->f.ioctl = init_closure_func(&fd->ioctl, fdesc_ioctl, uvm_ioctl);
        f->f.mmap = init_closure_func(&fd->mmap, fdesc_mmap, uvm_mmap);
        f->f.close = init_closure_func(&fd->close, fdesc_close, uvm_close);
        fd->f = f;
        status = uvm_va_space_create(fd);
    }
    else {
        NV_KFREE(fd, sizeof(*fd));
    }

    return -nv_status_to_errno(status);
}

bool uvm_file_is_nvidia_uvm(uvm_fd filp)
{
    return (filp != NULL);
}

static int uvm_chardev_create(void)
{
    spec_file_open open;

    open = closure(heap_locked(get_kernel_heaps()), uvm_open);
    assert(open != INVALID_ADDRESS);
    if (create_special_file("/dev/nvidia-uvm", open, 0, 0)) {
        return 0;
    } else {
        UVM_ERR_PRINT("create_special_file failed\n");
        deallocate_closure(open);
        return -ENOMEM;
    }
}

static void uvm_chardev_exit(void)
{
}

int uvm_init(void)
{
    bool initialized_globals = false;
    bool added_device = false;
    int ret;

    NV_STATUS status = uvm_global_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_global_init() failed: %s\n", nvstatusToString(status));
        ret = -ENODEV;
        goto error;
    }
    initialized_globals = true;

    ret = uvm_chardev_create();
    if (ret != 0) {
        UVM_ERR_PRINT("uvm_chardev_create failed: %d\n", ret);
        goto error;
    }
    added_device = true;

    ret = uvm_tools_init(g_uvm_base_dev);
    if (ret != 0) {
        UVM_ERR_PRINT("uvm_tools_init() failed: %d\n", ret);
        goto error;
    }

    pr_info("Loaded the UVM driver, major device number %d.\n", MAJOR(g_uvm_base_dev));

    if (uvm_enable_builtin_tests)
        pr_info("Built-in UVM tests are enabled. This is a security risk.\n");


    // After Open RM is released, both the enclosing "#if" and this comment
    // block should be removed, because the uvm_hmm_is_enabled_system_wide()
    // check is both necessary and sufficient for reporting functionality.
    // Until that time, however, we need to avoid advertisting UVM's ability to
    // enable HMM functionality.

    if (uvm_hmm_is_enabled_system_wide())
        UVM_INFO_PRINT("HMM (Heterogeneous Memory Management) is enabled in the UVM driver.\n");


    return 0;

error:
    if (added_device)
        uvm_chardev_exit();

    if (initialized_globals)
        uvm_global_exit();

    UVM_ERR_PRINT("uvm init failed: %d\n", ret);

    return ret;
}
