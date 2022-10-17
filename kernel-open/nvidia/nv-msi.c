/*
 * SPDX-FileCopyrightText: Copyright (c) 2018 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "nv-msi.h"
#include "nv-proto.h"

#if defined(NV_LINUX_PCIE_MSI_SUPPORTED)
void NV_API_CALL nv_init_msi(nv_state_t *nv)
{
}

define_closure_function(0, 0, void, nvidia_isr_msix)
{
    nv_nanos_state_t *nvl = struct_from_field(closure_self(), nv_nanos_state_t *, isr_msix);
    thunk isr = (thunk)&nvl->isr;

    // nvidia_isr_msix() is called for each of the MSI-X vectors and they can
    // run in parallel on different CPUs (cores), but this is not currently
    // supported by nvidia_isr() and its children. As a big hammer fix just
    // spinlock around the nvidia_isr() call to serialize them.
    //
    // At this point interrupts are disabled on the CPU running our ISR (see
    // comments for nv_default_irq_flags()) so a plain spinlock is enough.
    NV_SPIN_LOCK(&nvl->msix_isr_lock);

    apply(isr);

    NV_SPIN_UNLOCK(&nvl->msix_isr_lock);
}

define_closure_function(0, 0, void, nvidia_isr_msix_kthread_bh)
{
    nv_nanos_state_t *nvl = struct_from_field(closure_self(), nv_nanos_state_t *, isr_msix_bh);

    //
    // Synchronize kthreads servicing bottom halves for different MSI-X vectors
    // as they share same pre-allocated alt-stack.
    //
    os_acquire_mutex(nvl->msix_bh_mutex);
    // os_acquire_mutex can only fail if we cannot sleep and we can

    nvidia_isr_common_bh(nvl);

    os_release_mutex(nvl->msix_bh_mutex);
}

void NV_API_CALL nv_init_msix(nv_state_t *nv)
{
    nv_nanos_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);
    int num_intr = 0;
    int rc = 0;

    NV_SPIN_LOCK_INIT(&nvl->msix_isr_lock);

    rc = os_alloc_mutex(&nvl->msix_bh_mutex);
    if (rc != 0)
        goto failed;

    num_intr = nv_get_max_irq(nvl->pci_dev);

    if (num_intr > NV_RM_MAX_MSIX_LINES)
    {
        NV_DEV_PRINTF(NV_DBG_INFO, nv, "Reducing MSI-X count from %d to the "
                               "driver-supported maximum %d.\n", num_intr, NV_RM_MAX_MSIX_LINES);
        num_intr = NV_RM_MAX_MSIX_LINES;
    }

    NV_KMALLOC(nvl->irq_count, sizeof(nv_irq_count_info_t) * num_intr);

    if (nvl->irq_count == NULL)
    {
        NV_DEV_PRINTF(NV_DBG_ERRORS, nv, "Failed to allocate counter for MSI-X entries.\n");
        goto failed;
    }
    else
    {
        memset(nvl->irq_count, 0,  sizeof(nv_irq_count_info_t) * num_intr);
        nvl->current_num_irq_tracked = 0;
    }
    rc = nv_pci_enable_msix(nvl, num_intr);
    if (rc != NV_OK)
        goto failed;

    nv->flags |= NV_FLAG_USES_MSIX;
    return;

failed:
    nv->flags &= ~NV_FLAG_USES_MSIX;

    if (nvl->irq_count)
    {
        NV_KFREE(nvl->irq_count, sizeof(nv_irq_count_info_t) * num_intr);
    }

    if (nvl->msix_bh_mutex)
    {
        os_free_mutex(nvl->msix_bh_mutex);
        nvl->msix_bh_mutex = NULL;
    }
    NV_DEV_PRINTF(NV_DBG_ERRORS, nv, "Failed to enable MSI-X.\n");
}

NvS32 NV_API_CALL nv_request_msix_irq(nv_nanos_state_t *nvl)
{
    int i;
    int j;
    thunk h = init_closure(&nvl->isr_msix, nvidia_isr_msix);
    int rc = NV_ERR_INVALID_ARGUMENT;

    init_closure(&nvl->isr_msix_bh, nvidia_isr_msix_kthread_bh);
    for (i = 0; i < nvl->num_intr; i++)
    {
        rc = pci_setup_msix(nvl->pci_dev, i, h, nv_device_name);
        if (rc < 0)
        {
            for( j = 0; j < i; j++)
            {
                pci_teardown_msix(nvl->pci_dev, j);
            }
            break;
        }
        rc = 0;
    }

    return rc;
}
#endif
