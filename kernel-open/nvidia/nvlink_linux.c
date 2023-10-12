/*
 * SPDX-FileCopyrightText: Copyright (c) 2015-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "conftest.h"

#include "nvlink_os.h"
#include "nvlink_linux.h"
#include "nvlink_errors.h"
#include "nvlink_export.h"
#include "nv-nanos.h"
#include "nv-procfs.h"
#include "nv-time.h"
#include "nvlink_caps.h"

#define MAX_ERROR_STRING           512

typedef struct nvlink_file_private
{
    struct
    {
        /* A duped file descriptor for fabric_mgmt capability */
        int fabric_mgmt;
    } capability_fds;
} nvlink_file_private_t;

#define NVLINK_SET_FILE_PRIVATE(filp, data) ((filp)->private_data = (data))
#define NVLINK_GET_FILE_PRIVATE(filp) ((nvlink_file_private_t *)(filp)->private_data)

typedef struct
{
    struct mutex    lock;
    NvBool          initialized;
    dev_t           devno;
    int             opened;
    int             major_devnum;
} _nvlink_drvctx;


// nvlink driver local state
static _nvlink_drvctx nvlink_drvctx;

#if defined(CONFIG_PROC_FS)
#define NV_DEFINE_SINGLE_NVLINK_PROCFS_FILE(name) \
    NV_DEFINE_SINGLE_PROCFS_FILE_READ_ONLY(name, nv_system_pm_lock)
#endif

#define NVLINK_PROCFS_DIR "driver/nvidia-nvlink"

static struct proc_dir_entry *nvlink_procfs_dir = NULL;

#if defined(CONFIG_PROC_FS)
    static int nvlink_is_procfs_available = 1;
#endif

static struct proc_dir_entry *nvlink_permissions = NULL;

static void nvlink_permissions_exit(void)
{
    if (!nvlink_permissions)
    {
        return;
    }

    nvlink_permissions = NULL;
}

static int nvlink_permissions_init(void)
{
    return 0;
}

static void nvlink_procfs_exit(void)
{
    nvlink_permissions_exit();

    if (!nvlink_procfs_dir)
    {
        return;
    }

    nvlink_procfs_dir = NULL;
}

static int nvlink_procfs_init(void)
{
    int rc = 0;

    rc = nvlink_permissions_init();
    if (rc < 0)
    {
        goto cleanup;
    }

    return 0;

cleanup:

    nvlink_procfs_exit();

    return rc;
}

#define NV_FILE_INODE(file) (file)->f_inode

int nvlink_core_init(void)
{
    NvlStatus ret_val;
    int rc;

    if (NV_TRUE == nvlink_drvctx.initialized)
    {
        nvlink_print(NVLINK_DBG_ERRORS, "nvlink core interface already initialized\n");
        return -EBUSY;
    }

    mutex_init(&nvlink_drvctx.lock, 0);

    ret_val = nvlink_lib_initialize();
    if (NVL_SUCCESS != ret_val)
    {
        nvlink_print(NVLINK_DBG_ERRORS,  "Failed to initialize driver : %d\n", ret_val);
        rc = -ENODEV;
        goto nvlink_lib_initialize_fail;
    }

    rc = nvlink_procfs_init();
    if (rc < 0)
    {
        goto procfs_init_fail;
    }

    rc = nvlink_cap_init(NVLINK_PROCFS_DIR);
    if (rc < 0)
    {
        nvlink_print(NVLINK_DBG_ERRORS, " Unable to create capability\n");
        goto cap_init_fail;
    }

    nvlink_drvctx.initialized = NV_TRUE;

    return 0;

cap_init_fail:
    nvlink_procfs_exit();

procfs_init_fail:
    nvlink_lib_unload();

nvlink_lib_initialize_fail:
    return rc;
}

void nvlink_core_exit(void)
{
    if (NV_FALSE == nvlink_drvctx.initialized)
    {
        return;
    }

    nvlink_cap_exit();

    nvlink_procfs_exit();

    nvlink_lib_unload();
}

void
nvlink_print
(
    const char *file,
    int         line,
    const char *function,
    int         log_level,
    const char *fmt,
    ...
)
{
    va_list arglist;
    char    nv_string[MAX_ERROR_STRING];

    va_start(arglist, fmt);
    os_vsnprintf(nv_string, sizeof(nv_string), fmt, arglist);
    va_end(arglist);

    nv_string[sizeof(nv_string) - 1] = '\0';
    printk("nvidia-nvlink: %s", nv_string);
}

void * nvlink_malloc(NvLength size)
{
   return kmalloc(size, 0);
}

void nvlink_free(void *ptr)
{
    return kfree(ptr);
}

char * nvlink_strcpy(char *dest, const char *src)
{
    runtime_memcpy(dest, src, runtime_strlen(src) + 1);
    return dest;
}

int nvlink_strcmp(const char *dest, const char *src)
{
    return strcmp(dest, src);
}

NvLength nvlink_strlen(const char *s)
{
    return strlen(s);
}

int nvlink_snprintf(char *dest, NvLength size, const char *fmt, ...)
{
    va_list arglist;
    int chars_written;

    va_start(arglist, fmt);
    chars_written = os_vsnprintf(dest, size, fmt, arglist);
    va_end(arglist);

    return chars_written;
}

NvU32 nvlink_memRd32(const volatile void * address)
{
    return (*(const volatile NvU32*)(address));
}

void nvlink_memWr32(volatile void *address, NvU32 data)
{
    (*(volatile NvU32 *)(address)) = data;
}

NvU64 nvlink_memRd64(const volatile void * address)
{
    return (*(const volatile NvU64 *)(address));
}

void nvlink_memWr64(volatile void *address, NvU64 data)
{
    (*(volatile NvU64 *)(address)) = data;
}

void * nvlink_memset(void *dest, int value, NvLength size)
{
     return memset(dest, value, size);
}

void * nvlink_memcpy(void *dest, const void *src, NvLength size)
{
    return memcpy(dest, src, size);
}

int nvlink_memcmp(const void *s1, const void *s2, NvLength size)
{
    return memcmp(s1, s2, size);
}

/*
 * Sleep for specified milliseconds. Yields the CPU to scheduler.
 */
void nvlink_sleep(unsigned int ms)
{
    NV_STATUS status;

    status = nv_sleep_ms(ms);

    if (status !=  NV_OK)
    {
        nvlink_print(NVLINK_DBG_ERRORS, "NVLink: requested sleep duration"
                         " %d msec exceeded %d msec\n",
                         ms, NV_MAX_ISR_DELAY_MS);
    }
}

void nvlink_assert(int cond)
{
    if ((cond) == 0x0)
    {
        nvlink_print(NVLINK_DBG_ERRORS, "NVLink: Assertion failed!\n");

        dbg_breakpoint();
    }
}

void * nvlink_allocLock(void)
{
    struct semaphore *sema;

    sema = nvlink_malloc(sizeof(*sema));
    if (sema == NULL)
    {
        nvlink_print(NVLINK_DBG_ERRORS, "Failed to allocate sema!\n");
        return NULL;
    }
    sema_init(sema, 1);

    return sema;
}

void nvlink_acquireLock(void *hLock)
{
    down(hLock);
}

void nvlink_releaseLock(void *hLock)
{
    up(hLock);
}

void nvlink_freeLock(void *hLock)
{
    if (NULL == hLock)
    {
        return;
    }

    NVLINK_FREE(hLock);
}

NvBool nvlink_isLockOwner(void *hLock)
{
    return NV_TRUE;
}

NvlStatus nvlink_acquire_fabric_mgmt_cap(void *osPrivate, NvU64 capDescriptor)
{
    int dup_fd = -1;
    nvlink_file_private_t *private_data = (nvlink_file_private_t *)osPrivate;

    if (private_data == NULL)
    {
        return NVL_BAD_ARGS;
    }

    dup_fd = nvlink_cap_acquire((int)capDescriptor,
                                NVLINK_CAP_FABRIC_MANAGEMENT);
    if (dup_fd < 0)
    {
        return NVL_ERR_OPERATING_SYSTEM;
    }

    private_data->capability_fds.fabric_mgmt = dup_fd;
    return NVL_SUCCESS;
}

int nvlink_is_fabric_manager(void *osPrivate)
{
    nvlink_file_private_t *private_data = (nvlink_file_private_t *)osPrivate;

    /* Make sure that fabric mgmt capbaility fd is valid */
    if ((private_data == NULL) ||
        (private_data->capability_fds.fabric_mgmt < 0))
    {
        return 0;
    }

    return 1;
}

int nvlink_is_admin(void)
{
    return NV_IS_SUSER();
}
