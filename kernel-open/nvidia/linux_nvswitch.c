/*
 * SPDX-FileCopyrightText: Copyright (c) 2016-2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "linux_nvswitch.h"

#include "conftest.h"
#include "nvlink_errors.h"
#include "nvlink_linux.h"
#include "nvCpuUuid.h"
#include "nv-time.h"
#include "nvlink_caps.h"

#include "ioctl_nvswitch.h"

const static struct
{
    NvlStatus status;
    int err;
} nvswitch_status_map[] = {
    { NVL_ERR_GENERIC,                  -EIO        },
    { NVL_NO_MEM,                       -ENOMEM     },
    { NVL_BAD_ARGS,                     -EINVAL     },
    { NVL_ERR_INVALID_STATE,            -EIO        },
    { NVL_ERR_NOT_SUPPORTED,            -EOPNOTSUPP },
    { NVL_NOT_FOUND,                    -EINVAL     },
    { NVL_ERR_STATE_IN_USE,             -EBUSY      },
    { NVL_ERR_NOT_IMPLEMENTED,          -ENOSYS     },
    { NVL_ERR_INSUFFICIENT_PERMISSIONS, -EPERM      },
    { NVL_ERR_OPERATING_SYSTEM,         -EIO        },
    { NVL_MORE_PROCESSING_REQUIRED,     -EAGAIN     },
    { NVL_SUCCESS,                       0          },
};

int
nvswitch_map_status
(
    NvlStatus status
)
{
    int err = -EIO;
    NvU32 i;
    NvU32 limit = sizeof(nvswitch_status_map) / sizeof(nvswitch_status_map[0]);

    for (i = 0; i < limit; i++)
    {
        if (nvswitch_status_map[i].status == status ||
            nvswitch_status_map[i].status == -status)
        {
            err = nvswitch_status_map[i].err;
            break;
        }
    }

    return err;
}

#if !defined(IRQF_SHARED)
#define IRQF_SHARED SA_SHIRQ
#endif

#define NV_FILE_INODE(file) (file)->f_inode

//
// nvidia_nvswitch_mknod uses minor number 255 to create nvidia-nvswitchctl
// node. Hence, if NVSWITCH_CTL_MINOR is changed, then NV_NVSWITCH_CTL_MINOR
// should be updated. See nvdia-modprobe-utils.h
//
#define NVSWITCH_CTL_MINOR 255
#define NVSWITCH_MINOR_COUNT (NVSWITCH_CTL_MINOR + 1)

// 32 bit hex value - including 0x prefix. (10 chars)
#define NVSWITCH_REGKEY_VALUE_LEN 10

static char *NvSwitchRegDwords;

static char *NvSwitchBlacklist;

//
// Locking:
//   We handle nvswitch driver locking in the OS layer. The nvswitch lib
//   layer does not have its own locking. It relies on the OS layer for
//   atomicity.
//
//   All locking is done with sleep locks. We use threaded MSI interrupts to
//   facilitate this.
//
//   When handling a request from a user context we use the interruptible
//   version to enable a quick ^C return if there is lock contention.
//
//   nvswitch.driver_mutex is used to protect driver's global state, "struct
//   NVSWITCH". The driver_mutex is taken during .probe, .remove, .open,
//   .close, and nvswitch-ctl .ioctl operations.
//
//   nvswitch_dev.device_mutex is used to protect per-device state, "struct
//   NVSWITCH_DEV", once a device is opened. The device_mutex is taken during
//   .ioctl, .poll and other background tasks.
//
//   The kernel guarantees that .close won't happen while .ioctl and .poll
//   are going on and without successful .open one can't execute any file ops.
//   This behavior guarantees correctness of the locking model.
//
//   If .close is invoked and holding the lock which is also used by threaded
//   tasks such as interrupt, driver will deadlock while trying to stop such
//   tasks. For example, when threaded interrupts are enabled, free_irq() calls
//   kthread_stop() to flush pending interrupt tasks. The locking model
//   makes sure that such deadlock cases don't happen.
//
// Lock ordering:
//   nvswitch.driver_mutex
//   nvswitch_dev.device_mutex
//
// Note:
//   Due to bug 2856314, nvswitch_dev.device_mutex is taken when calling
//   nvswitch_post_init_device() in nvswitch_probe().
//

// Per-chip driver state is defined in linux_nvswitch.h

// Global driver state
typedef struct
{
    NvBool initialized;
    u64 devno;
    atomic_t count;
    struct mutex driver_mutex;
    struct list devices;
} NVSWITCH;

static NVSWITCH nvswitch = {0};

// NvSwitch event
typedef struct nvswitch_event_t
{
    NvBool            event_pending;
} nvswitch_event_t;

typedef struct nvswitch_file_private
{
    NVSWITCH_DEV     *nvswitch_dev;
    nvswitch_event_t file_event;
    struct
    {
        /* A duped file descriptor for fabric_mgmt capability */
        int fabric_mgmt;
    } capability_fds;
} nvswitch_file_private_t;

#define NVSWITCH_SET_FILE_PRIVATE(filp, data) ((filp)->private_data = (data))
#define NVSWITCH_GET_FILE_PRIVATE(filp) ((nvswitch_file_private_t *)(filp)->private_data)

typedef struct {
    void *kernel_params;                // Kernel copy of ioctl parameters
    unsigned long kernel_params_size;   // Size of ioctl params according to user
} IOCTL_STATE;

#define NVSWITCH_CTL_CHECK_PARAMS(type, size) (sizeof(type) == size ? 0 : -EINVAL)

static void
nvswitch_ctl_exit
(
    void
)
{
}

static int
nvswitch_ctl_init
(
    int major
)
{
    return 0;
}

//
// Initialize nvswitch driver SW state.  This is currently called
// from the RM as a backdoor interface, and not by the Linux device
// manager
//
int
nvswitch_init
(
    void
)
{
    int rc;

    if (nvswitch.initialized)
    {
        printk(KERN_ERR "nvidia-nvswitch: Interface already initialized\n");
        return -EBUSY;
    }

    BUILD_BUG_ON(NVSWITCH_DEVICE_INSTANCE_MAX >= NVSWITCH_MINOR_COUNT);

    mutex_init(&nvswitch.driver_mutex, 0);

    INIT_LIST_HEAD(&nvswitch.devices);

    rprintf("nvidia-nvswitch: Major: %d Minor: %d\n",
           MAJOR(nvswitch.devno),
           MINOR(nvswitch.devno));

    rc = nvswitch_procfs_init();
    if (rc < 0)
    {
        goto nvswitch_procfs_init_fail;
    }

    rc = nvswitch_ctl_init(MAJOR(nvswitch.devno));
    if (rc < 0)
    {
        goto nvswitch_ctl_init_fail;
    }

    nvswitch.initialized = NV_TRUE;

    return 0;

nvswitch_ctl_init_fail:
nvswitch_procfs_init_fail:
    return rc;
}

//
// Clean up driver state on exit.  Currently called from RM backdoor call,
// and not by the Linux device manager.
//
void
nvswitch_exit
(
    void
)
{
    if (NV_FALSE == nvswitch.initialized)
    {
        return;
    }

    nvswitch_ctl_exit();

    nvswitch_procfs_exit();

    WARN_ON(!list_empty(&nvswitch.devices));

    nvswitch.initialized = NV_FALSE;
}

//
// Get current time in seconds.nanoseconds
// In this implementation, the time is from epoch time
// (midnight UTC of January 1, 1970)
//
NvU64
nvswitch_os_get_platform_time
(
    void
)
{
    struct timespec64 ts;

    ktime_get_raw_ts64(&ts);
    return (NvU64) timespec64_to_ns(&ts);
}

void
nvswitch_os_print
(
    const int  log_level,
    const char *fmt,
    ...
)
{
    buffer b = little_stack_buffer(16 * KB);
    buffer f = alloca_wrap_cstring(fmt);
    va_list arglist;

    va_start(arglist, fmt);
    vbprintf(b, f, &arglist);
    buffer_print(b);
    va_end(arglist);
}

void
nvswitch_os_override_platform
(
    void *os_handle,
    NvBool *rtlsim
)
{
    // Never run on RTL
    *rtlsim = NV_FALSE;
}

NvlStatus
nvswitch_os_read_registery_binary
(
    void *os_handle,
    const char *name,
    NvU8 *data,
    NvU32 length
)
{
    return -NVL_ERR_NOT_SUPPORTED;
}

NvU32
nvswitch_os_get_device_count
(
    void
)
{
    return NV_ATOMIC_READ(nvswitch.count);
}

//
// A helper to convert a string to an unsigned int.
//
// The string should be NULL terminated.
// Only works with base16 values.
//
static int
nvswitch_os_strtouint
(
    char *str,
    unsigned int *data
)
{
    char *p;
    unsigned long long val;

    if (!str || !data)
    {
        return -EINVAL;
    }

    *data = 0;
    val = 0;
    p = str;

    while (*p != '\0')
    {
        if ((tolower(*p) == 'x') && (*str == '0') && (p == str + 1))
        {
            p++;
        }
        else if (*p >='0' && *p <= '9')
        {
            val = val * 16 + (*p - '0');
            p++;
        }
        else if (tolower(*p) >= 'a' && tolower(*p) <= 'f')
        {
            val = val * 16 + (tolower(*p) - 'a' + 10);
            p++;
        }
        else
        {
            return -EINVAL;
        }
    }

    if (val > 0xFFFFFFFF)
    {
        return -EINVAL;
    }

    *data = (unsigned int)val;

    return 0;
}

NvlStatus
nvswitch_os_read_registry_dword
(
    void *os_handle,
    const char *name,
    NvU32 *data
)
{
    char *regkey, *regkey_val_start, *regkey_val_end;
    char regkey_val[NVSWITCH_REGKEY_VALUE_LEN + 1];
    NvU32 regkey_val_len = 0;

    *data = 0;

    if (!NvSwitchRegDwords)
    {
        return -NVL_ERR_GENERIC;
    }

    regkey = strstr(NvSwitchRegDwords, name);
    if (!regkey)
    {
        return -NVL_ERR_GENERIC;
    }

    regkey = strchr(regkey, '=');
    if (!regkey)
    {
        return -NVL_ERR_GENERIC;
    }

    regkey_val_start = regkey + 1;

    regkey_val_end = strchr(regkey, ';');
    if (!regkey_val_end)
    {
        regkey_val_end = strchr(regkey, '\0');
    }

    regkey_val_len = regkey_val_end - regkey_val_start;
    if (regkey_val_len > NVSWITCH_REGKEY_VALUE_LEN || regkey_val_len == 0)
    {
        return -NVL_ERR_GENERIC;
    }

    strncpy(regkey_val, regkey_val_start, regkey_val_len);
    regkey_val[regkey_val_len] = '\0';

    if (nvswitch_os_strtouint(regkey_val, data) != 0)
    {
        return -NVL_ERR_GENERIC;
    }

    return NVL_SUCCESS;
}

static NvBool
_nvswitch_is_space(const char ch)
{
    return ((ch == ' ') || ((ch >= '\t') && (ch <= '\r')));
}

static char *
_nvswitch_remove_spaces(const char *in)
{
    unsigned int len = nvswitch_os_strlen(in) + 1;
    const char *in_ptr;
    char *out, *out_ptr;

    out = nvswitch_os_malloc(len);
    if (out == NULL)
        return NULL;

    in_ptr = in;
    out_ptr = out;

    while (*in_ptr != '\0')
    {
        if (!_nvswitch_is_space(*in_ptr))
            *out_ptr++ = *in_ptr;
        in_ptr++;
    }
    *out_ptr = '\0';

    return out;
}

/*
 * Compare given string UUID with the NvSwitchBlacklist registry parameter string and
 * return whether the UUID is in the NvSwitch blacklist
 */
NvBool
nvswitch_os_is_uuid_in_blacklist
(
    NvUuid *uuid
)
{
    char *list;
    char uuid_string[NVSWITCH_UUID_STRING_LENGTH];

    if (NvSwitchBlacklist == NULL)
        return NV_FALSE;

    if (nvswitch_uuid_to_string(uuid, uuid_string, NVSWITCH_UUID_STRING_LENGTH) == 0)
        return NV_FALSE;

    if ((list = _nvswitch_remove_spaces(NvSwitchBlacklist)) == NULL)
        return NV_FALSE;

    nvswitch_os_free(list);
    return NV_FALSE;
}


NvlStatus
nvswitch_os_alloc_contig_memory
(
    void *os_handle,
    void **virt_addr,
    NvU32 size,
    NvBool force_dma32
)
{
    unsigned long nv_gfp_addr = 0;

    if (!virt_addr)
        return -NVL_BAD_ARGS;

    NV_GET_FREE_PAGES(nv_gfp_addr, find_order(size >> PAGELOG));

    if(!nv_gfp_addr)
    {
        pr_err("nvidia-nvswitch: unable to allocate kernel memory\n");
        return -NVL_NO_MEM;
    }

    *virt_addr = (void *)nv_gfp_addr;

    return NVL_SUCCESS;
}

void
nvswitch_os_free_contig_memory
(
    void *os_handle,
    void *virt_addr,
    NvU32 size
)
{
    NV_FREE_PAGES((unsigned long)virt_addr, find_order(size >> PAGELOG));
}

NvlStatus
nvswitch_os_map_dma_region
(
    void *os_handle,
    void *cpu_addr,
    NvU64 *dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    struct pci_dev *pdev = (struct pci_dev *)os_handle;

    if (!pdev || !cpu_addr || !dma_handle)
        return -NVL_BAD_ARGS;

    *dma_handle = physical_from_virtual(cpu_addr);

    return NVL_SUCCESS;
}

NvlStatus
nvswitch_os_unmap_dma_region
(
    void *os_handle,
    void *cpu_addr,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    struct pci_dev *pdev = (struct pci_dev *)os_handle;

    if (!pdev || !cpu_addr)
        return -NVL_BAD_ARGS;

    return NVL_SUCCESS;
}

NvlStatus
nvswitch_os_set_dma_mask
(
    void *os_handle,
    NvU32 dma_addr_width
)
{
    struct pci_dev *pdev = (struct pci_dev *)os_handle;

    if (!pdev)
        return -NVL_BAD_ARGS;

    return NVL_SUCCESS;
}

NvlStatus
nvswitch_os_sync_dma_region_for_cpu
(
    void *os_handle,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    struct pci_dev *pdev = (struct pci_dev *)os_handle;

    if (!pdev)
        return -NVL_BAD_ARGS;

    memory_barrier();

    return NVL_SUCCESS;
}

NvlStatus
nvswitch_os_sync_dma_region_for_device
(
    void *os_handle,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    struct pci_dev *pdev = (struct pci_dev *)os_handle;

    if (!pdev)
        return -NVL_BAD_ARGS;

    memory_barrier();

    return NVL_SUCCESS;
}

static inline void *
_nvswitch_os_malloc
(
    NvLength size
)
{
    void *ptr = NULL;

    if (!NV_MAY_SLEEP())
    {
        if (size <= NVSWITCH_KMALLOC_LIMIT)
        {
            ptr = kmalloc(size, NV_GFP_ATOMIC);
        }
    }
    else
    {
        if (size <= NVSWITCH_KMALLOC_LIMIT)
        {
            ptr = kmalloc(size, NV_GFP_NO_OOM);
        }

        if (ptr == NULL)
        {
            ptr = vmalloc(size);
        }
    }

    return ptr;
}

void *
nvswitch_os_malloc_trace
(
    NvLength size,
    const char *file,
    NvU32 line
)
{
#if defined(NV_MEM_LOGGER)
    void *ptr = _nvswitch_os_malloc(size);
    if (ptr)
    {
        nv_memdbg_add(ptr, size, file, line);
    }

    return ptr;
#else
    return _nvswitch_os_malloc(size);
#endif
}

static inline void
_nvswitch_os_free
(
    void *ptr
)
{
    if (!ptr)
        return;

    if (is_vmalloc_addr(ptr))
    {
        vfree(ptr);
    }
    else
    {
        kfree(ptr);
    }
}

void
nvswitch_os_free
(
    void *ptr
)
{
#if defined (NV_MEM_LOGGER)
    if (ptr == NULL)
        return;

    nv_memdbg_remove(ptr, 0, NULL, 0);

    return _nvswitch_os_free(ptr);
#else
    return _nvswitch_os_free(ptr);
#endif
}

NvLength
nvswitch_os_strlen
(
    const char *str
)
{
    return strlen(str);
}

char*
nvswitch_os_strncpy
(
    char *dest,
    const char *src,
    NvLength length
)
{
    return strncpy(dest, src, length);
}

int
nvswitch_os_strncmp
(
    const char *s1,
    const char *s2,
    NvLength length
)
{
    NvLength l1 = runtime_strlen(s1) + 1;
    NvLength l2 = runtime_strlen(s2) + 1;
    length = MIN(length, l1);
    length = MIN(length, l2);
    return memcmp(s1, s2, length);
}

void *
nvswitch_os_memset
(
    void *dest,
    int value,
    NvLength size
)
{
     return memset(dest, value, size);
}

void *
nvswitch_os_memcpy
(
    void *dest,
    const void *src,
    NvLength size
)
{
    return memcpy(dest, src, size);
}

int
nvswitch_os_memcmp
(
    const void *s1,
    const void *s2,
    NvLength size
)
{
    return memcmp(s1, s2, size);
}

NvU32
nvswitch_os_mem_read32
(
    const volatile void * address
)
{
    return (*(const volatile NvU32*)(address));
}

void
nvswitch_os_mem_write32
(
    volatile void *address,
    NvU32 data
)
{
    (*(volatile NvU32 *)(address)) = data;
}

NvU64
nvswitch_os_mem_read64
(
    const volatile void * address
)
{
    return (*(const volatile NvU64 *)(address));
}

void
nvswitch_os_mem_write64
(
    volatile void *address,
    NvU64 data
)
{
    (*(volatile NvU64 *)(address)) = data;
}

int
nvswitch_os_snprintf
(
    char *dest,
    NvLength size,
    const char *fmt,
    ...
)
{
    va_list arglist;
    int chars_written;

    va_start(arglist, fmt);
    chars_written = os_vsnprintf(dest, size, fmt, arglist);
    va_end(arglist);

    return chars_written;
}

int
nvswitch_os_vsnprintf
(
    char *buf,
    NvLength size,
    const char *fmt,
    va_list arglist
)
{
    return os_vsnprintf(buf, size, fmt, arglist);
}

void
nvswitch_os_assert_log
(
    int cond,
    const char *fmt,
    ...
)
{
    if(cond == 0x0)
    {
        va_list arglist;
        char fmt_printk[NVSWITCH_LOG_BUFFER_SIZE];

        va_start(arglist, fmt);
        os_vsnprintf(fmt_printk, sizeof(fmt_printk), fmt, arglist);
        va_end(arglist);
        buffer_print(alloca_wrap_cstring(fmt_printk));
         dbg_breakpoint();
    }
}

/*
 * Sleep for specified milliseconds. Yields the CPU to scheduler.
 */
void
nvswitch_os_sleep
(
    unsigned int ms
)
{
    NV_STATUS status;
    status = nv_sleep_ms(ms);

    if (status != NV_OK)
    {
        nvswitch_os_print(NVSWITCH_DBG_LEVEL_ERROR, "NVSwitch: requested"
                              " sleep duration %d msec exceeded %d msec\n",
                              ms, NV_MAX_ISR_DELAY_MS);
    }
}

NvlStatus
nvswitch_os_acquire_fabric_mgmt_cap
(
    void *osPrivate,
    NvU64 capDescriptor
)
{
    int dup_fd = -1;
    nvswitch_file_private_t *private_data = (nvswitch_file_private_t *)osPrivate;

    if (private_data == NULL)
    {
        return -NVL_BAD_ARGS;
    }

    dup_fd = nvlink_cap_acquire((int)capDescriptor,
                                NVLINK_CAP_FABRIC_MANAGEMENT);
    if (dup_fd < 0)
    {
        return -NVL_ERR_OPERATING_SYSTEM;
    }

    private_data->capability_fds.fabric_mgmt = dup_fd;
    return NVL_SUCCESS;
}

int
nvswitch_os_is_fabric_manager
(
    void *osPrivate
)
{
    nvswitch_file_private_t *private_data = (nvswitch_file_private_t *)osPrivate;

    /* Make sure that fabric mgmt capbaility fd is valid */
    if ((private_data == NULL) ||
        (private_data->capability_fds.fabric_mgmt < 0))
    {
        return 0;
    }

    return 1;
}

int
nvswitch_os_is_admin
(
    void
)
{
    return NV_IS_SUSER();
}

#define NV_KERNEL_RELEASE    0
#define NV_KERNEL_VERSION    1
#define NV_KERNEL_SUBVERSION 42

NvlStatus
nvswitch_os_get_os_version
(
    NvU32 *pMajorVer,
    NvU32 *pMinorVer,
    NvU32 *pBuildNum
)
{
    if (pMajorVer)
        *pMajorVer = NV_KERNEL_RELEASE;
    if (pMinorVer)
        *pMinorVer = NV_KERNEL_VERSION;
    if (pBuildNum)
        *pBuildNum = NV_KERNEL_SUBVERSION;

    return NVL_SUCCESS;
}

/*!
 * @brief: OS specific handling to add an event.
 */
NvlStatus
nvswitch_os_add_client_event
(
    void            *osHandle,
    void            *osPrivate,
    NvU32           eventId
)
{
    return NVL_SUCCESS;
}

/*!
 * @brief: OS specific handling to remove all events corresponding to osPrivate.
 */
NvlStatus
nvswitch_os_remove_client_event
(
    void            *osHandle,
    void            *osPrivate
)
{
    return NVL_SUCCESS;
}

/*!
 * @brief: OS specific handling to notify an event.
 */
NvlStatus
nvswitch_os_notify_client_event
(
    void *osHandle,
    void *osPrivate,
    NvU32 eventId
)
{
    nvswitch_file_private_t *private_data = (nvswitch_file_private_t *)osPrivate;

    if (private_data == NULL)
    {
        return -NVL_BAD_ARGS;
    }

    private_data->file_event.event_pending = NV_TRUE;

    return NVL_SUCCESS;
}

/*!
 * @brief: Gets OS specific support for the REGISTER_EVENTS ioctl
 */
NvlStatus
nvswitch_os_get_supported_register_events_params
(
    NvBool *many_events,
    NvBool *os_descriptor
)
{
    *many_events   = NV_FALSE;
    *os_descriptor = NV_FALSE;
    return NVL_SUCCESS;
}
