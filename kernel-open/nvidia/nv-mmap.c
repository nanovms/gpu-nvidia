/*
 * SPDX-FileCopyrightText: Copyright (c) 1999-2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#define  __NO_VERSION__

#include "os-interface.h"
#include "nv-nanos.h"
#include "nv_speculation_barrier.h"

int nv_encode_caching(
    pgprot_t *prot,
    NvU32     cache_type,
    nv_memory_type_t memory_type
)
{
    pgprot_t tmp;

    if (prot == NULL)
    {
        prot = &tmp;
    }

    switch (cache_type)
    {
        case NV_MEMORY_UNCACHED_WEAK:
#if defined(NV_PGPROT_UNCACHED_WEAK)
            *prot = NV_PGPROT_UNCACHED_WEAK(*prot);
            break;
#endif
        case NV_MEMORY_UNCACHED:
            *prot = (memory_type == NV_MEMORY_TYPE_SYSTEM) ?
                    NV_PGPROT_UNCACHED(*prot) :
                    NV_PGPROT_UNCACHED_DEVICE(*prot);
            break;
#if defined(NV_PGPROT_WRITE_COMBINED) && \
    defined(NV_PGPROT_WRITE_COMBINED_DEVICE)
        case NV_MEMORY_DEFAULT:
        case NV_MEMORY_WRITECOMBINED:
            if (NV_ALLOW_WRITE_COMBINING(memory_type))
            {
                *prot = (memory_type == NV_MEMORY_TYPE_FRAMEBUFFER) ?
                        NV_PGPROT_WRITE_COMBINED_DEVICE(*prot) :
                        NV_PGPROT_WRITE_COMBINED(*prot);
                break;
            }

            /*
             * If WC support is unavailable, we need to return an error
             * code to the caller, but need not print a warning.
             *
             * For frame buffer memory, callers are expected to use the
             * UC- memory type if we report WC as unsupported, which
             * translates to the effective memory type WC if a WC MTRR
             * exists or else UC.
             */
            return 1;
#endif
        case NV_MEMORY_CACHED:
            if (!NV_ALLOW_CACHING(memory_type))
            {
                nv_printf(NV_DBG_ERRORS,
                    "NVRM: VM: memory type %d does not allow caching!\n",
                    memory_type);
                return 1;
            }
            break;

        default:
            nv_printf(NV_DBG_ERRORS,
                "NVRM: VM: cache type %d not supported for memory type %d!\n",
                cache_type, memory_type);
            return 1;
    }
    return 0;
}

sysreturn static nvidia_mmap_peer_io(
    vmap vma,
    nv_alloc_t *at,
    NvU64 page_index,
    NvU64 pages, pageflags flags
)
{
    sysreturn ret;
    NvU64 start;
    NvU64 size;

    BUG_ON(!at->flags.contig);

    start = at->page_table[page_index]->phys_addr;
    size = pages * PAGE_SIZE;

    ret = nv_io_remap_page_range(vma, start, size, flags);
    if (ret == INVALID_PHYSICAL)
        ret = -ENOMEM;

    return ret;
}

sysreturn static nvidia_mmap_sysmem(
    vmap vma,
    nv_alloc_t *at,
    NvU64 page_index,
    NvU64 pages, pageflags flags
)
{
    NvU64 j;
    int ret = 0;
    unsigned long start = 0;

    NV_ATOMIC_INC(at->usage_count);

    start = vma->node.r.start;

    for (j = page_index; j < (page_index + pages); j++)
    {
        /*
         * For PPC64LE build, nv_array_index_no_speculate() is not defined
         * therefore call nv_speculation_barrier().
         * When this definition is added, this platform check should be removed.
         */
#if !defined(NVCPU_PPC64LE)
        j = nv_array_index_no_speculate(j, (page_index + pages));
#else
        nv_speculation_barrier();
#endif

#if defined(NV_VGPU_KVM_BUILD)
        if (at->flags.guest)
        {
            ret = nv_remap_page_range(vma, start, at->page_table[j]->phys_addr,
                                      PAGE_SIZE, vma->vm_page_prot);
        }
        else
#endif
        {
            remap(start, at->page_table[j]->phys_addr, PAGE_SIZE, flags);
        }

        if (ret)
        {
            NV_ATOMIC_DEC(at->usage_count);
            return -EAGAIN;
        }
        start += PAGE_SIZE;
    }

    return vma->node.r.start;
}

sysreturn nvidia_mmap_helper(nv_state_t *nv, nvfd nvlfp, nvidia_stack_t *sp, vmap vma, u64 offset)
{
    sysreturn ret;
    const nv_alloc_mapping_context_t *mmap_context = &nvlfp->mmap_context;
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);
    pageflags flags = pageflags_from_vmflags(vma->flags);

    if (nvlfp == NULL)
        return -EINVAL;

    /*
     * If mmap context is not valid on this file descriptor, this mapping wasn't
     * previously validated with the RM so it must be rejected.
     */
    if (!mmap_context->valid)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: VM: invalid mmap\n");
        return -EINVAL;
    }

    if (vma->node_offset != 0)
    {
        return -EINVAL;
    }

    /*
     * Nvidia device node(nvidia#) maps device's BAR memory,
     * Nvidia control node(nvidiactrl) maps system memory.
     */
    if (!NV_IS_CTL_DEVICE(nv))
    {
        NvU64 mmap_start = mmap_context->mmap_start;
        NvU64 mmap_length = mmap_context->mmap_size;
        NvU64 access_start = mmap_context->access_start;
        NvU64 access_len = mmap_context->access_size;

        // validate the size
        if (NV_VMA_SIZE(vma) != mmap_length)
        {
            return -ENXIO;
        }

        if (IS_REG_OFFSET(nv, access_start, access_len))
        {
            if (nv_encode_caching(&flags, NV_MEMORY_UNCACHED,
                        NV_MEMORY_TYPE_REGISTERS))
            {
                return -ENXIO;
            }
        }
        else if (IS_FB_OFFSET(nv, access_start, access_len))
        {
            if (IS_UD_OFFSET(nv, access_start, access_len))
            {
                if (nv_encode_caching(&flags, NV_MEMORY_UNCACHED,
                            NV_MEMORY_TYPE_FRAMEBUFFER))
                {
                    return -ENXIO;
                }
            }
            else
            {
                if (nv_encode_caching(&flags,
                        rm_disable_iomap_wc() ? NV_MEMORY_UNCACHED : mmap_context->caching, 
                        NV_MEMORY_TYPE_FRAMEBUFFER))
                {
                    if (nv_encode_caching(&flags,
                            NV_MEMORY_UNCACHED_WEAK, NV_MEMORY_TYPE_FRAMEBUFFER))
                    {
                        return -ENXIO;
                    }
                }
            }
        }

        down(&nvl->mmap_lock);
        if (nvl->safe_to_mmap)
        {
            nvl->all_mappings_revoked = NV_FALSE;

            if ((ret = nv_io_remap_page_range(vma, mmap_start, mmap_length, flags)) ==
                    INVALID_PHYSICAL)
            {
                up(&nvl->mmap_lock);
                return -EAGAIN;
            }
        }
        else
        {
            ret = -EAGAIN;
        }
        up(&nvl->mmap_lock);
    }
    else
    {
        nv_alloc_t *at;
        NvU64 page_index;
        NvU64 pages;
        NvU64 mmap_size;

        at = (nv_alloc_t *)mmap_context->alloc;
        page_index = mmap_context->page_index;
        mmap_size = NV_VMA_SIZE(vma);
        pages = mmap_size >> PAGE_SHIFT;

        if ((page_index + pages) > at->num_pages)
        {
            return -ERANGE;
        }

        if (at->flags.peer_io)
        {
            if (nv_encode_caching(&flags,
                                  at->cache_type,
                                  NV_MEMORY_TYPE_DEVICE_MMIO))
            {
                return -ENXIO;
            }

            ret = nvidia_mmap_peer_io(vma, at, page_index, pages, flags);
        }
        else
        {
            if (nv_encode_caching(&flags,
                                  at->cache_type,
                                  NV_MEMORY_TYPE_SYSTEM))
            {
                return -ENXIO;
            }

            ret = nvidia_mmap_sysmem(vma, at, page_index, pages, flags);
        }

        if (ret)
        {
            return ret;
        }

        NV_PRINT_AT(NV_DBG_MEMINFO, at);
    }

    return ret;
}

void
nv_revoke_gpu_mappings_locked(
    nv_state_t *nv
)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);

    /* Revoke all mappings for every open file */

    nvl->all_mappings_revoked = NV_TRUE;
}

NV_STATUS NV_API_CALL nv_revoke_gpu_mappings(
    nv_state_t *nv
)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);

    // Mapping revocation is only supported for GPU mappings.
    if (NV_IS_CTL_DEVICE(nv))
    {
        return NV_ERR_NOT_SUPPORTED;
    }

    down(&nvl->mmap_lock);

    nv_revoke_gpu_mappings_locked(nv);

    up(&nvl->mmap_lock);

    return NV_OK;
}

void NV_API_CALL nv_acquire_mmap_lock(
    nv_state_t *nv
)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);
    down(&nvl->mmap_lock);
}

void NV_API_CALL nv_release_mmap_lock(
    nv_state_t *nv
)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);
    up(&nvl->mmap_lock);
}

NvBool NV_API_CALL nv_get_all_mappings_revoked_locked(
    nv_state_t *nv
)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);

    // Caller must hold nvl->mmap_lock for all decisions based on this
    return nvl->all_mappings_revoked;
}

void NV_API_CALL nv_set_safe_to_mmap_locked(
    nv_state_t *nv,
    NvBool safe_to_mmap
)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);

    // Caller must hold nvl->mmap_lock

    /*
     * If nvl->safe_to_mmap is transitioning from TRUE to FALSE, we expect to
     * need to schedule a GPU wakeup callback when we fault.
     *
     * nvl->gpu_wakeup_callback_needed will be set to FALSE in nvidia_fault()
     * after scheduling the GPU wakeup callback, preventing us from scheduling
     * duplicates.
     */
    if (!safe_to_mmap && nvl->safe_to_mmap)
    {
        nvl->gpu_wakeup_callback_needed = NV_TRUE;
    }

    nvl->safe_to_mmap = safe_to_mmap;
}
