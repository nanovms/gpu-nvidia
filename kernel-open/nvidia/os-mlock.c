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

static inline int nv_follow_pfn(unsigned long address,
                                unsigned long *pfn)
{
#if defined(NV_UNSAFE_FOLLOW_PFN_PRESENT)
    return unsafe_follow_pfn(vma, address, pfn);
#else
    u64 phys = physical_from_virtual(pointer_from_u64(address));
    *pfn = phys >> PAGE_SHIFT;
    return 0;
#endif
}

/*!
 * @brief Locates the PFNs for a user IO address range, and converts those to
 *        their associated PTEs.
 *
 * @param[in]     start Beginning of the virtual address range of the IO PTEs.
 * @param[in]     page_count Number of pages containing the IO range being
 *                           mapped.
 * @param[in,out] pte_array Storage array for PTE addresses. Must be large
 *                          enough to contain at least page_count pointers.
 *
 * @return NV_OK if the PTEs were identified successfully, error otherwise.
 */
static NV_STATUS get_io_ptes(NvUPtr start,
                             NvU64 page_count,
                             NvU64 **pte_array)
{
    NvU64 i;
    unsigned long pfn;

    for (i = 0; i < page_count; i++)
    {
        if (nv_follow_pfn((start + (i * PAGE_SIZE)), &pfn) < 0)
        {
            return NV_ERR_INVALID_ADDRESS;
        }

        pte_array[i] = (NvU64 *)(pfn << PAGE_SHIFT);

        if (i == 0)
            continue;

        //
        // This interface is to be used for contiguous, uncacheable I/O regions.
        // Internally, osCreateOsDescriptorFromIoMemory() checks the user-provided
        // flags against this, and creates a single memory descriptor with the same
        // attributes. This check ensures the actual mapping supplied matches the
        // user's declaration. Ensure the PFNs represent a contiguous range,
        // error if they do not.
        //
        if ((NvU64)pte_array[i] != (((NvU64)pte_array[i-1]) + PAGE_SIZE))
        {
            return NV_ERR_INVALID_ADDRESS;
        }
    }
    return NV_OK;
}

/*!
 * @brief Pins user IO pages that have been mapped to the user processes virtual
 *        address space with remap_pfn_range.
 *
 * @param[in]     start Beginning of the virtual address range of the IO pages.
 * @param[in]     page_count Number of pages to pin from start.
 * @param[in,out] page_array Storage array for pointers to the pinned pages.
 *                           Must be large enough to contain at least page_count
 *                           pointers.
 *
 * @return NV_OK if the pages were pinned successfully, error otherwise.
 */
static NV_STATUS get_io_pages(NvUPtr start,
                              NvU64 page_count,
                              NvU64 *page_array)
{
    NV_STATUS rmStatus = NV_OK;
    NvU64 i, pinned = 0;
    unsigned long pfn;

    for (i = 0; i < page_count; i++)
    {
        if ((nv_follow_pfn((start + (i * PAGE_SIZE)), &pfn) < 0) ||
            (!pfn_valid(pfn)))
        {
            rmStatus = NV_ERR_INVALID_ADDRESS;
            break;
        }

        // Page-backed memory mapped to userspace with remap_pfn_range
        page_array[i] = pfn << PAGE_SHIFT;
        pinned++;
    }

    if (pinned < page_count)
    {
        rmStatus = NV_ERR_INVALID_ADDRESS;
    }

    return rmStatus;
}

NV_STATUS NV_API_CALL os_lookup_user_io_memory(
    void   *address,
    NvU64   page_count,
    NvU64 **pte_array,
    void  **page_array
)
{
    NV_STATUS rmStatus;
    unsigned long pfn;
    NvUPtr start = (NvUPtr)address;
    void **result_array;

    if (!NV_MAY_SLEEP())
    {
        nv_printf(NV_DBG_ERRORS,
            "NVRM: %s(): invalid context!\n", __FUNCTION__);
        return NV_ERR_NOT_SUPPORTED;
    }

    rmStatus = os_alloc_mem((void **)&result_array, (page_count * sizeof(NvP64)));
    if (rmStatus != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                "NVRM: failed to allocate page table!\n");
        return rmStatus;
    }

    if (nv_follow_pfn(start, &pfn) < 0)
    {
        rmStatus = NV_ERR_INVALID_ADDRESS;
        goto done;
    }

    if (pfn_valid(pfn))
    {
        rmStatus = get_io_pages(start, page_count, (NvU64 *)result_array);
        if (rmStatus == NV_OK)
            *page_array = (void *)result_array;
    }
    else
    {
        rmStatus = get_io_ptes(start, page_count, (NvU64 **)result_array);
        if (rmStatus == NV_OK)
            *pte_array = (NvU64 *)result_array;
    }

done:
    if (rmStatus != NV_OK)
    {
        os_free_mem(result_array);
    }

    return rmStatus;
}

NV_STATUS NV_API_CALL os_lock_user_pages(
    void   *address,
    NvU64   page_count,
    void  **page_array,
    NvU32   flags
)
{
    NV_STATUS rmStatus;
    NvU64 *user_pages;
    NvU64 pinned;
    NvBool write = DRF_VAL(_LOCK_USER_PAGES, _FLAGS, _WRITE, flags), force = 0;
    int ret;

    if (!NV_MAY_SLEEP())
    {
        nv_printf(NV_DBG_ERRORS,
            "NVRM: %s(): invalid context!\n", __FUNCTION__);
        return NV_ERR_NOT_SUPPORTED;
    }

    rmStatus = os_alloc_mem((void **)&user_pages,
            (page_count * sizeof(*user_pages)));
    if (rmStatus != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                "NVRM: failed to allocate page table!\n");
        return rmStatus;
    }

    ret = NV_GET_USER_PAGES((unsigned long)address,
                            page_count, write, force, user_pages, NULL);
    pinned = ret;

    if (ret < 0)
    {
        os_free_mem(user_pages);
        return NV_ERR_INVALID_ADDRESS;
    }
    else if (pinned < page_count)
    {
        os_free_mem(user_pages);
        return NV_ERR_INVALID_ADDRESS;
    }

    *page_array = user_pages;

    return NV_OK;
}

NV_STATUS NV_API_CALL os_unlock_user_pages(
    NvU64  page_count,
    void  *page_array
)
{
    NvU64 *user_pages = page_array;

    os_free_mem(user_pages);

    return NV_OK;
}
