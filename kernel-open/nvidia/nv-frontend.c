/*
 * SPDX-FileCopyrightText: Copyright (c) 2012-2013 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "os-interface.h"
#include "nv-nanos.h"
#include "nv-reg.h"
#include "nv-frontend.h"

/*
 * MODULE_IMPORT_NS() is added by commit id 8651ec01daeda
 * ("module: add support for symbol namespaces") in 5.4
 */
#if defined(MODULE_IMPORT_NS)

/*
 * DMA_BUF namespace is added by commit id 16b0314aa746
 * ("dma-buf: move dma-buf symbols into the DMA_BUF module namespace") in 5.16
 */
MODULE_IMPORT_NS(DMA_BUF);

#endif

static NvU32 nv_num_instances;

// lock required to protect table.
struct semaphore nv_module_table_lock;

// minor number table
nvidia_module_t *nv_minor_num_table[NV_FRONTEND_CONTROL_DEVICE_MINOR_MAX + 1];

int nvidia_init_module(void);
void nvidia_exit_module(void);

/* Helper functions */

static int add_device(nvidia_module_t *module, nv_nanos_state_t *device, NvBool all)
{
    NvU32 i;
    int rc = -1;

    // look for free a minor number and assign unique minor number to this device
    for (i = 0; i <= NV_FRONTEND_CONTROL_DEVICE_MINOR_MIN; i++)
    {
        if (nv_minor_num_table[i] == NULL)
        {
            nv_minor_num_table[i] = module;
            device->minor_num = i;
            if (all == NV_TRUE)
            {
                device = device->next;
                if (device == NULL)
                {
                    rc = 0;
                    break;
                }
            }
            else
            {
                rc = 0;
                break;
            }
        }
    }
    return rc;
}

static int remove_device(nvidia_module_t *module, nv_nanos_state_t *device)
{
    int rc = -1;

    // remove this device from minor_number table
    if ((device != NULL) && (nv_minor_num_table[device->minor_num] != NULL))
    {
        nv_minor_num_table[device->minor_num] = NULL;
        device->minor_num = 0;
        rc = 0;
    }
    return rc;
}

closure_function(1, 1, sysreturn, nvidia_frontend_open,
                 u32, minor,
                 file f)
{
    sysreturn rc = -ENODEV;
    nvidia_module_t *module = NULL;

    NvU32 minor_num = bound(minor);

    down(&nv_module_table_lock);
    module = nv_minor_num_table[minor_num];

    if (module != NULL)
    {
        rc = module->open(minor_num, f);
    }

    up(&nv_module_table_lock);
    return rc;
}

/* Export functions */

int nvidia_register_module(nvidia_module_t *module)
{
    int rc = 0;
    NvU32 ctrl_minor_num;
    spec_file_open open;

    down(&nv_module_table_lock);
    if (module->instance >= NV_MAX_MODULE_INSTANCES)
    {
        printk("NVRM: NVIDIA module instance %d registration failed.\n",
                module->instance);
        rc = -EINVAL;
        goto done;
    }

    ctrl_minor_num = NV_FRONTEND_CONTROL_DEVICE_MINOR_MAX - module->instance;
    open = closure(heap_locked(get_kernel_heaps()), nvidia_frontend_open, ctrl_minor_num);
    if (open == INVALID_ADDRESS) {
        rc = -ENOMEM;
        goto done;
    }
    if (!create_special_file(ss("/dev/nvidiactl"), open, 0,
        makedev(NV_MAJOR_DEVICE_NUMBER, NV_CONTROL_DEVICE_MINOR))) {
        deallocate_closure(open);
        rc = -ENOSPC;
        goto done;
    }
    nv_minor_num_table[ctrl_minor_num] = module;
    nv_num_instances++;
done:
    up(&nv_module_table_lock);

    return rc;
}
EXPORT_SYMBOL(nvidia_register_module);

int nvidia_unregister_module(nvidia_module_t *module)
{
    int rc = 0;
    NvU32 ctrl_minor_num;

    down(&nv_module_table_lock);

    ctrl_minor_num = NV_FRONTEND_CONTROL_DEVICE_MINOR_MAX - module->instance;
    if (nv_minor_num_table[ctrl_minor_num] == NULL)
    {
        printk("NVRM: NVIDIA module for %d instance does not exist\n",
                module->instance);
        rc = -1;
    }
    else
    {
        nv_minor_num_table[ctrl_minor_num] = NULL;
        nv_num_instances--;
    }

    up(&nv_module_table_lock);

    return rc;
}
EXPORT_SYMBOL(nvidia_unregister_module);

int nvidia_frontend_add_device(nvidia_module_t *module, nv_nanos_state_t * device)
{
    int rc = -1;
    NvU32 ctrl_minor_num;

    down(&nv_module_table_lock);
    ctrl_minor_num = NV_FRONTEND_CONTROL_DEVICE_MINOR_MAX - module->instance;
    if (nv_minor_num_table[ctrl_minor_num] == NULL)
    {
        printk("NVRM: NVIDIA module for %d instance does not exist\n",
                module->instance);
        rc = -1;
    }
    else
    {
        rc = add_device(module, device, NV_FALSE);
        if (rc == 0) {
            NvU32 minor = device->minor_num;
            spec_file_open open = closure(heap_locked(get_kernel_heaps()), nvidia_frontend_open,
                minor);

            if (open != INVALID_ADDRESS) {
                char file_path[] = "/dev/nvidiaXXX";

                if (minor < 10) {
                    file_path[11] = '0' + minor;
                    file_path[12] = '\0';
                } else if (minor < 100) {
                    file_path[11] = '0' + minor / 10;
                    file_path[12] = '0' + minor % 10;
                    file_path[13] = '\0';
                } else {
                    file_path[11] = '0' + minor / 100;
                    file_path[12] = '0' + (minor / 10) % 10;
                    file_path[13] = '0' + minor % 10;
                }
                if (!create_special_file(isstring(file_path, sizeof(file_path) - 1), open, 0,
                    makedev(NV_MAJOR_DEVICE_NUMBER, minor))) {
                    deallocate_closure(open);
                    rc = -1;
                }
            } else {
                rc = -1;
            }
            if (rc < 0)
                remove_device(module, device);
        }
    }
    up(&nv_module_table_lock);

    return rc;
}
EXPORT_SYMBOL(nvidia_frontend_add_device);

int nvidia_frontend_remove_device(nvidia_module_t *module, nv_nanos_state_t * device)
{
    int rc = 0;
    NvU32 ctrl_minor_num;

    down(&nv_module_table_lock);
    ctrl_minor_num = NV_FRONTEND_CONTROL_DEVICE_MINOR_MAX - module->instance;
    if (nv_minor_num_table[ctrl_minor_num] == NULL)
    {
        printk("NVRM: NVIDIA module for %d instance does not exist\n",
                module->instance);
        rc = -1;
    }
    else
    {
        rc = remove_device(module, device);
    }
    up(&nv_module_table_lock);

    return rc;
}
EXPORT_SYMBOL(nvidia_frontend_remove_device);

int init(status_handler complete)
{
    extern int uvm_init(void);

    // initialise nvidia module table;
    nv_num_instances = 0;
    memset(nv_minor_num_table, 0, sizeof(nv_minor_num_table));
    NV_INIT_MUTEX(&nv_module_table_lock);

    if ((nvidia_init_module() < 0) || (uvm_init() < 0))
    {
        return KLIB_INIT_FAILED;
    }
    return KLIB_INIT_OK;
}
