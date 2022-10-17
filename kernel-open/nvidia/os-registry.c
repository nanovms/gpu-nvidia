/*
 * SPDX-FileCopyrightText: Copyright (c) 2000-2018 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#define NV_DEFINE_REGISTRY_KEY_TABLE
#include "os-interface.h"
#include "nv-nanos.h"
#include "nv-reg.h"
#include "nv-gpu-info.h"

/*!
 * @brief This function parses the registry keys per GPU device. It accepts a
 * semicolon separated list of key=value pairs. The first key value pair MUST be
 * "pci=DDDD:BB:DD.F;" where DDDD is Domain, BB is Bus Id, DD is device slot
 * number and F is the Function. This PCI BDF is used to identify which GPU to
 * assign the registry keys that follows next.
 * If a GPU corresponding to the value specified in "pci=DDDD:BB:DD.F;" is NOT
 * found, then all the registry keys that follows are skipped, until we find next
 * valid pci identified "pci=DDDD:BB:DD.F;". Following are the valid formats for
 * the value of the "pci" string:
 * 1)  bus:slot                 : Domain and function defaults to 0.
 * 2)  domain:bus:slot          : Function defaults to 0.
 * 3)  domain:bus:slot.func     : Complete PCI dev id string.
 *
 *
 * @param[in]  sp       pointer to nvidia_stack_t struct.
 *
 * @return NV_OK if succeeds, or NV_STATUS error code otherwise.
 */
NV_STATUS nv_parse_per_device_option_string(nvidia_stack_t *sp)
{
    NV_STATUS status = NV_OK;
    char *option_string = NULL;

    if (NVreg_RegistryDwordsPerDevice != NULL)
    {
        if ((option_string = rm_remove_spaces(NVreg_RegistryDwordsPerDevice)) == NULL)
        {
            return NV_ERR_GENERIC;
        }

        os_free_mem(option_string);
    }
    return status;
}

/*
 * Compare given string UUID with the GpuBlacklist or ExcludedGpus registry
 * parameter string and return whether the UUID is in the GPU exclusion list
 */
NvBool nv_is_uuid_in_gpu_exclusion_list(const char *uuid)
{
    const char *input;
    char *list;

    //
    // When both NVreg_GpuBlacklist and NVreg_ExcludedGpus are defined
    // NVreg_ExcludedGpus takes precedence.
    //
    if (NVreg_ExcludedGpus != NULL)
        input = NVreg_ExcludedGpus;
    else if (NVreg_GpuBlacklist != NULL)
        input = NVreg_GpuBlacklist;
    else
        return NV_FALSE;

    if ((list = rm_remove_spaces(input)) == NULL)
        return NV_FALSE;

    os_free_mem(list);
    return NV_FALSE;
}

NV_STATUS NV_API_CALL os_registry_init(void)
{
    nv_parm_t *entry;
    unsigned int i;
    nvidia_stack_t *sp = NULL;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        return NV_ERR_NO_MEMORY;
    }

    if (NVreg_RmMsg != NULL)
    {
        rm_write_registry_string(sp, NULL,
                "RmMsg", NVreg_RmMsg, strlen(NVreg_RmMsg));
    }

    rm_parse_option_string(sp, NVreg_RegistryDwords);

    for (i = 0; (entry = &nv_parms[i])->name != NULL; i++)
    {
        rm_write_registry_dword(sp, NULL, entry->name, *entry->data);
    }

    nv_kmem_cache_free_stack(sp);

    return NV_OK;
}
