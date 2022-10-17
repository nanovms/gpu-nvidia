/*
 * SPDX-FileCopyrightText: Copyright (c) 2019-2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "export_nvswitch.h"
#include "nv-pci.h"
#include "nv-ibmnpu.h"
#include "nv-frontend.h"
#include "nv-msi.h"
#include "nv-hypervisor.h"

#if defined(NV_VGPU_KVM_BUILD)
#include "nv-vgpu-vfio-interface.h"
#endif

#if defined(NV_SEQ_READ_ITER_PRESENT)
#include <linux/seq_file.h>
#include <linux/kernfs.h>
#endif

static void
nv_check_and_exclude_gpu(
    nvidia_stack_t *sp,
    nv_state_t *nv
)
{
    char *uuid_str;

    uuid_str = rm_get_gpu_uuid(sp, nv);
    if (uuid_str == NULL)
    {
        NV_DEV_PRINTF(NV_DBG_INFO, nv, "Unable to read UUID");
        return;
    }

    if (nv_is_uuid_in_gpu_exclusion_list(uuid_str))
    {
        NV_STATUS rm_status = rm_exclude_adapter(sp, nv);
        if (rm_status != NV_OK)
        {
            NV_DEV_PRINTF_STATUS(NV_DBG_ERRORS, nv, rm_status,
                          "Failed to exclude GPU %s", uuid_str);
            goto done;
        }
        nv->flags |= NV_FLAG_EXCLUDE;
        NV_DEV_PRINTF(NV_DBG_INFO, nv, "Excluded GPU %s successfully\n",
                      uuid_str);
    }

done:
    os_free_mem(uuid_str);
}

/* find nvidia devices and set initial state */
closure_function(0, 1, boolean, nv_pci_probe,
                 pci_dev, d)
{
    u16 dev_class, dev_subclass, dev_vendor, dev_id, sub_vendor, sub_dev;
    nv_state_t *nv = NULL;
    nv_nanos_state_t *nvl = NULL;
    unsigned int i, j;
    int flags = 0;
    nvidia_stack_t *sp = NULL;
    NvBool prev_nv_ats_supported = nv_ats_supported;

    dev_class = pci_get_class(d);
    dev_subclass = pci_get_subclass(d);
    dev_vendor = pci_get_vendor(d);
    if ((dev_vendor != PCI_VENDOR_ID_NVIDIA) || (dev_class != PCIC_DISPLAY) ||
        (dev_subclass != PCIS_3D))
    {
        return false;
    }
    dev_class = (dev_class << 8) | dev_subclass;
    dev_id = pci_get_device(d);
    sub_vendor = pci_get_subsystem_vendor(d);
    sub_dev = pci_get_subdevice(d);
    nv_printf(NV_DBG_SETUP, "NVRM: probing 0x%x 0x%x, class 0x%x\n",
        dev_vendor, dev_id, dev_class);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        return false;
    }


#ifdef NV_PCI_SRIOV_SUPPORT
    if (pci_dev->is_virtfn)
    {
#if defined(NV_VGPU_KVM_BUILD)
        nvl = pci_get_drvdata(pci_dev->physfn);
        if (!nvl)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: Aborting probe for VF %04x:%02x:%02x.%x "
                      "since PF is not bound to nvidia driver.\n",
                       0, d->bus, d->slot, d->function);
            goto failed;
        }

        if (pci_dev->dev.bus->iommu_ops == NULL) 
        {
            nv = NV_STATE_PTR(nvl);
            if (rm_is_iommu_needed_for_sriov(sp, nv))
            {
                nv_printf(NV_DBG_ERRORS, "NVRM: Aborting probe for VF %04x:%02x:%02x.%x "
                          "since IOMMU is not present on the system.\n",
                           NV_PCI_DOMAIN_NUMBER(pci_dev), NV_PCI_BUS_NUMBER(pci_dev),
                           NV_PCI_SLOT_NUMBER(pci_dev), PCI_FUNC(pci_dev->devfn));
                goto failed;
            }
        }

        if (nvidia_vgpu_vfio_probe(pci_dev) != NV_OK)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: Failed to register device to vGPU VFIO module");
            goto failed;
        }

        nv_kmem_cache_free_stack(sp);
        return true;
#else
        nv_printf(NV_DBG_ERRORS, "NVRM: Ignoring probe for VF %04x:%02x:%02x.%x ",
                  NV_PCI_DOMAIN_NUMBER(pci_dev), NV_PCI_BUS_NUMBER(pci_dev),
                  NV_PCI_SLOT_NUMBER(pci_dev), PCI_FUNC(pci_dev->devfn));

        goto failed;
#endif /* NV_VGPU_KVM_BUILD */
    }
#endif /* NV_PCI_SRIOV_SUPPORT */


    if (!rm_is_supported_pci_device(
                (dev_class >> 8) & 0xFF,
                dev_class & 0xFF,
                dev_vendor,
                dev_id,
                sub_vendor,
                sub_dev,
                NV_FALSE /* print_legacy_warning */))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: ignoring the legacy GPU %04x:%02x:%02x.%x\n",
                  0, d->bus, d->slot, d->function);
        goto failed;
    }

    num_probed_nv_devices++;

    pci_enable_io_and_memory(d);

    NV_KMALLOC(nvl, sizeof(nv_nanos_state_t));
    if (nvl == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate memory\n");
        goto err_not_supported;
    }

    os_mem_set(nvl, 0, sizeof(nv_nanos_state_t));

    nv  = NV_STATE_PTR(nvl);

    nvl->pci_dev           = d;

    nv->pci_info.vendor_id = dev_vendor;
    nv->pci_info.device_id = dev_id;
    nv->subsystem_id       = sub_dev;
    nv->subsystem_vendor   = sub_vendor;
    nv->os_state           = (void *) nvl;
    nv->dma_dev            = &nvl->dma_dev;
    nv->pci_info.domain    = 0;
    nv->pci_info.bus       = d->bus;
    nv->pci_info.slot      = d->slot;
    nv->handle             = d;
    nv->flags             |= flags;

    if (!nv_lock_init_locks(sp, nv))
    {
        goto err_not_supported;
    }

    nvl->all_mappings_revoked = NV_TRUE;
    nvl->safe_to_mmap = NV_TRUE;
    nvl->gpu_wakeup_callback_needed = NV_TRUE;
    INIT_LIST_HEAD(&nvl->open_files);

    for (i = 0, j = 0; i < NVRM_PCICFG_NUM_BARS && j < NV_GPU_NUM_BARS; i++)
    {
        u32 base = pci_cfgread(d, PCIR_BAR(i), 4);
        u64 size = 0;
        u64 addr = 0;

        if ((base & PCI_BAR_B_TYPE_MASK) == PCI_BAR_MEMORY)
        {
            size = pci_bar_size(d, PCI_BAR_MEMORY, base & PCI_BAR_B_MEMORY_MASK, i);
            addr = base & ~PCI_BAR_B_MEMORY_MASK;
            if (base & PCI_BAR_F_64BIT)
                addr |= ((u64)pci_cfgread(d, PCIR_BAR(++i), 4)) << 32;
        }
        if (addr && size)
        {
            nv->bars[j].offset = PCIR_BAR(i);
            nv->bars[j].cpu_address = addr;
            nv->bars[j].size = size;
            j++;
        }
    }
    nv->regs = &nv->bars[NV_GPU_BAR_INDEX_REGS];
    nv->fb   = &nv->bars[NV_GPU_BAR_INDEX_FB];

    nv_init_ibmnpu_info(nv);





#if defined(NVCPU_PPC64LE)
    // Use HW NUMA support as a proxy for ATS support. This is true in the only
    // PPC64LE platform where ATS is currently supported (IBM P9).
    nv_ats_supported &= nv_platform_supports_numa(nvl);
#else





#endif
    if (nv_ats_supported)
    {
        NV_DEV_PRINTF(NV_DBG_INFO, nv, "ATS supported by this GPU!\n");
    }
    else
    {
        NV_DEV_PRINTF(NV_DBG_INFO, nv, "ATS not supported by this GPU. "
                      "Disabling ATS support for all the GPUs in the system!\n");
    }

    pci_set_bus_master(d);

#if defined(CONFIG_VGA_ARB) && !defined(NVCPU_PPC64LE)
#if defined(VGA_DEFAULT_DEVICE)
#if defined(NV_VGA_TRYGET_PRESENT)
    vga_tryget(VGA_DEFAULT_DEVICE, VGA_RSRC_LEGACY_MASK);
#endif
#endif
    vga_set_legacy_decoding(pci_dev, VGA_RSRC_NONE);
#endif

    if ((rm_is_supported_device(sp, nv)) != NV_OK)
        goto err_not_supported;

    if (!rm_init_private_state(sp, nv))
    {
        NV_DEV_PRINTF(NV_DBG_ERRORS, nv, "rm_init_private_state() failed!\n");
        goto err_zero_dev;
    }

    nv_printf(NV_DBG_INFO,
              "NVRM: PCI:%04x:%02x:%02x.%x (%04x:%04x): BAR0 @ 0x%lx (%ldMB)\n",
              nv->pci_info.domain, nv->pci_info.bus, nv->pci_info.slot,
              d->function, nv->pci_info.vendor_id, nv->pci_info.device_id,
              nv->regs->cpu_address, (nv->regs->size >> 20));
    nv_printf(NV_DBG_INFO,
              "NVRM: PCI:%04x:%02x:%02x.%x (%04x:%04x): BAR1 @ 0x%lx (%ldMB)\n",
              nv->pci_info.domain, nv->pci_info.bus, nv->pci_info.slot,
              d->function, nv->pci_info.vendor_id, nv->pci_info.device_id,
              nv->fb->cpu_address, (nv->fb->size >> 20));

    num_nv_devices++;

    /*
     * The newly created nvl object is added to the nv_linux_devices global list
     * only after all the initialization operations for that nvl object are
     * completed, so as to protect against simultaneous lookup operations which
     * may discover a partially initialized nvl object in the list
     */
    LOCK_NV_LINUX_DEVICES();

    nv_linux_add_device_locked(nvl);

    UNLOCK_NV_LINUX_DEVICES();

    if (nvidia_frontend_add_device((void *)&nv_fops, nvl) != 0)
        goto err_remove_device;

#if defined(NV_PM_VT_SWITCH_REQUIRED_PRESENT)
    pm_vt_switch_required(nvl->dev, NV_TRUE);
#endif

    nv_procfs_add_gpu(nvl);

    /* Parse and set any per-GPU registry keys specified. */
    nv_parse_per_device_option_string(sp);

#if defined(NV_VGPU_KVM_BUILD)
    if (nvidia_vgpu_vfio_probe(nvl->pci_dev) != NV_OK)
    {
        NV_DEV_PRINTF(NV_DBG_ERRORS, nv, "Failed to register device to vGPU VFIO module");
        nvidia_frontend_remove_device((void *)&nv_fops, nvl);
        goto err_remove_device;
    }
#endif

    nv_check_and_exclude_gpu(sp, nv);

    rm_set_rm_firmware_requested(sp, nv);

#if defined(DPM_FLAG_NO_DIRECT_COMPLETE)
    dev_pm_set_driver_flags(nvl->dev, DPM_FLAG_NO_DIRECT_COMPLETE);
#elif defined(DPM_FLAG_NEVER_SKIP)
    dev_pm_set_driver_flags(nvl->dev, DPM_FLAG_NEVER_SKIP);
#endif

    /*
     * Dynamic power management should be enabled as the last step.
     * Kernel runtime power management framework can put the device
     * into the suspended state. Hardware register access should not be done
     * after enabling dynamic power management.
     */
    rm_enable_dynamic_power_management(sp, nv);
    nv_kmem_cache_free_stack(sp);

    return true;

err_remove_device:
    LOCK_NV_LINUX_DEVICES();
    nv_linux_remove_device_locked(nvl);
    UNLOCK_NV_LINUX_DEVICES();
    rm_cleanup_dynamic_power_management(sp, nv);
err_zero_dev:
    rm_free_private_state(sp, nv);
err_not_supported:
    nv_ats_supported = prev_nv_ats_supported;
    nv_destroy_ibmnpu_info(nv);
    nv_lock_destroy_locks(sp, nv);
    if (nvl != NULL)
    {
        NV_KFREE(nvl, sizeof(nv_nanos_state_t));
    }
failed:
    nv_kmem_cache_free_stack(sp);
    return false;
}

/*!
 * @brief This function accepts pci information corresponding to a GPU
 * and returns a reference to the nv_linux_state_t corresponding to that GPU.
 *
 * @param[in] domain            Pci domain number for the GPU to be found.
 * @param[in] bus               Pci bus number for the GPU to be found.
 * @param[in] slot              Pci slot number for the GPU to be found.
 * @param[in] function          Pci function number for the GPU to be found.
 *
 * @return Pointer to nv_linux_state_t for the GPU if it is found, or NULL otherwise.
 */
nv_nanos_state_t * find_pci(NvU32 domain, NvU8 bus, NvU8 slot, NvU8 function)
{
    nv_nanos_state_t *nvl = NULL;

    LOCK_NV_LINUX_DEVICES();

    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        nv_state_t *nv = NV_STATE_PTR(nvl);

        if (nv->pci_info.domain == domain &&
            nv->pci_info.bus == bus &&
            nv->pci_info.slot == slot &&
            nv->pci_info.function == function)
        {
            break;
        }
    }

    UNLOCK_NV_LINUX_DEVICES();
    return nvl;
}

int nvidia_dev_get_pci_info(const NvU8 *uuid, struct pci_dev **pci_dev_out,
    NvU64 *dma_start, NvU64 *dma_limit)
{
    nv_nanos_state_t *nvl;

    /* Takes nvl->ldata_lock */
    nvl = find_uuid(uuid);
    if (!nvl)
        return -ENODEV;

    *pci_dev_out = nvl->pci_dev;
    *dma_start = nvl->dma_dev.addressable_range.start;
    *dma_limit = nvl->dma_dev.addressable_range.limit;

    up(&nvl->ldata_lock);

    return 0;
}

NvU8 nv_find_pci_capability(struct pci_dev *pci_dev, NvU8 capability)
{
    u16 status = 0;

    status = pci_cfgread(pci_dev, PCIR_STATUS, 2);
    status &= 0x10; /* Support Capability List */
    if (!status)
        return 0;

    return pci_find_cap(pci_dev, capability);
}

#if defined(NV_PCI_ERROR_RECOVERY)
static pci_ers_result_t
nv_pci_error_detected(
    struct pci_dev *pci_dev,
    nv_pci_channel_state_t error
)
{
    nv_nanos_state_t *nvl = pci_get_drvdata(pci_dev);

    if ((nvl == NULL) || (nvl->pci_dev != pci_dev))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: %s: invalid device!\n", __FUNCTION__);
        return PCI_ERS_RESULT_NONE;
    }

    /*
     * Tell Linux to continue recovery of the device. The kernel will enable
     * MMIO for the GPU and call the mmio_enabled callback.
     */
    return PCI_ERS_RESULT_CAN_RECOVER;
}

static pci_ers_result_t
nv_pci_mmio_enabled(
    struct pci_dev *pci_dev
)
{
    NV_STATUS         status = NV_OK;
    nv_stack_t       *sp = NULL;
    nv_nanos_state_t *nvl = pci_get_drvdata(pci_dev);
    nv_state_t       *nv = NULL;

    if ((nvl == NULL) || (nvl->pci_dev != pci_dev))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: %s: invalid device!\n", __FUNCTION__);
        goto done;
    }

    nv = NV_STATE_PTR(nvl);

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: %s: failed to allocate stack!\n",
            __FUNCTION__);
        goto done;
    }

    NV_DEV_PRINTF(NV_DBG_ERRORS, nv, "A fatal error was detected.\n");

    /*
     * MMIO should be re-enabled now. If we still get bad reads, there's
     * likely something wrong with the adapter itself that will require a
     * reset. This should let us know whether the GPU has completely fallen
     * off the bus or just did something the host didn't like.
     */
    status = rm_is_supported_device(sp, nv);
    if (status != NV_OK)
    {
        NV_DEV_PRINTF(NV_DBG_ERRORS, nv,
            "The kernel has enabled MMIO for the device,\n"
            "NVRM: but it still appears unreachable. The device\n"
            "NVRM: will not function properly until it is reset.\n");
    }

    status = rm_log_gpu_crash(sp, nv);
    if (status != NV_OK)
    {
        NV_DEV_PRINTF_STATUS(NV_DBG_ERRORS, nv, status,
                      "Failed to log crash data\n");
        goto done;
    }

done:
    if (sp != NULL)
    {
        nv_kmem_cache_free_stack(sp);
    }

    /*
     * Tell Linux to abandon recovery of the device. The kernel might be able
     * to recover the device, but RM and clients don't yet support that.
     */
    return PCI_ERS_RESULT_DISCONNECT;
}

struct pci_error_handlers nv_pci_error_handlers = {
    .error_detected = nv_pci_error_detected,
    .mmio_enabled   = nv_pci_mmio_enabled,
};
#endif

#if defined(CONFIG_PM)
extern struct dev_pm_ops nv_pm_ops;
#endif

void nv_pci_unregister_driver(void)
{
    if (NVreg_RegisterPCIDriver == 0)
    {
        return;
    }
}

int nv_pci_register_driver(void)
{
    if (NVreg_RegisterPCIDriver == 0)
    {
        return 0;
    }
    pci_probe probe = closure(heap_locked(get_kernel_heaps()), nv_pci_probe);
    if (probe == INVALID_ADDRESS)
        return -1;
    register_pci_driver(probe, 0);
    pci_discover();
    return 0;
}
