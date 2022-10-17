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

#include "nv-nanos.h"
#include "nv-caps.h"
#include "nv-procfs.h"
#include "nv-hash.h"

extern int NVreg_ModifyDeviceFiles;

#define NV_CAP_DRV_MINOR_COUNT 8192

/* Hash table with 512 buckets */
#define NV_CAP_HASH_BITS 9
NV_DECLARE_HASHTABLE(g_nv_cap_hash_table, NV_CAP_HASH_BITS);

#define NV_CAP_HASH_SIZE NV_HASH_SIZE(g_nv_cap_hash_table)

#define nv_cap_hash_key(path) (nv_string_hash(path) % NV_CAP_HASH_SIZE)

typedef struct nv_cap_table_entry
{
    /* name must be the first element */
    const char *name;
    int minor;
    struct list hlist;
} nv_cap_table_entry_t;

#define NV_CAP_NUM_ENTRIES(_table) (sizeof(_table) / sizeof(_table[0]))

static nv_cap_table_entry_t g_nv_cap_nvlink_table[] =
{
    {"/driver/nvidia-nvlink/capabilities/fabric-mgmt"}
};

static nv_cap_table_entry_t g_nv_cap_mig_table[] =
{
    {"/driver/nvidia/capabilities/mig/config"},
    {"/driver/nvidia/capabilities/mig/monitor"}
};

#define NV_CAP_MIG_CI_ENTRIES(_gi)  \
    {_gi "/ci0/access"},            \
    {_gi "/ci1/access"},            \
    {_gi "/ci2/access"},            \
    {_gi "/ci3/access"},            \
    {_gi "/ci4/access"},            \
    {_gi "/ci5/access"},            \
    {_gi "/ci6/access"},            \
    {_gi "/ci7/access"}

#define NV_CAP_MIG_GI_ENTRIES(_gpu)       \
    {_gpu "/gi0/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi0"),   \
    {_gpu "/gi1/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi1"),   \
    {_gpu "/gi2/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi2"),   \
    {_gpu "/gi3/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi3"),   \
    {_gpu "/gi4/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi4"),   \
    {_gpu "/gi5/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi5"),   \
    {_gpu "/gi6/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi6"),   \
    {_gpu "/gi7/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi7"),   \
    {_gpu "/gi8/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi8"),   \
    {_gpu "/gi9/access"},                 \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi9"),   \
    {_gpu "/gi10/access"},                \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi10"),  \
    {_gpu "/gi11/access"},                \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi11"),  \
    {_gpu "/gi12/access"},                \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi12"),  \
    {_gpu "/gi13/access"},                \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi13"),  \
    {_gpu "/gi14/access"},                \
    NV_CAP_MIG_CI_ENTRIES(_gpu "/gi14")

static nv_cap_table_entry_t g_nv_cap_mig_gpu_table[] =
{
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu0/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu1/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu2/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu3/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu4/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu5/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu6/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu7/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu8/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu9/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu10/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu11/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu12/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu13/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu14/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu15/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu16/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu17/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu18/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu19/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu20/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu21/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu22/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu23/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu24/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu25/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu26/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu27/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu28/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu29/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu30/mig"),
    NV_CAP_MIG_GI_ENTRIES("/driver/nvidia/capabilities/gpu31/mig")
};

struct nv_cap
{
    char *path;
    char *name;
    int minor;
    int permissions;
    int modify;
    struct proc_dir_entry *parent;
    struct proc_dir_entry *entry;
};

#define NV_CAP_PROCFS_WRITE_BUF_SIZE 128

struct
{
    NvBool initialized;
    dev_t devno;
} g_nv_cap_drv;

#define NV_CAP_PROCFS_DIR "driver/nvidia-caps"
#define NV_CAP_NAME_BUF_SIZE 128

static int nv_cap_find_minor(char *path)
{
    return -1;
}

static void _nv_cap_table_init(nv_cap_table_entry_t *table, int count)
{
    int i;
    static int minor = 0;

    for (i = 0; i < count; i++)
    {
        table[i].minor = minor++;
        list_init_member(&table[i].hlist);
    }

    WARN_ON(minor > NV_CAP_DRV_MINOR_COUNT);
}

#define nv_cap_table_init(table) \
    _nv_cap_table_init(table, NV_CAP_NUM_ENTRIES(table))

static void nv_cap_tables_init(void)
{
    BUILD_BUG_ON(offsetof(nv_cap_table_entry_t *, name) != 0);

    nv_hash_init(g_nv_cap_hash_table);

    nv_cap_table_init(g_nv_cap_nvlink_table);
    nv_cap_table_init(g_nv_cap_mig_table);
    nv_cap_table_init(g_nv_cap_mig_gpu_table);
}

int NV_API_CALL nv_cap_validate_and_dup_fd(const nv_cap_t *cap, int fd)
{
    fdesc f;
    int dup_fd;

    if (cap == NULL)
    {
        return -1;
    }

    f = resolve_fd(current->p, fd);

    dup_fd = allocate_fd(current->p, f);
    fdesc_put(f);
    if (dup_fd < 0)
    {
    }

    return dup_fd;
}

void NV_API_CALL nv_cap_close_fd(int fd)
{
    if (fd == -1)
    {
        return;
    }

/*
 * From v4.17-rc1 (to v5.10.8) kernels have stopped exporting sys_close(fd)
 * and started exporting __close_fd, as of this commit:
 * 2018-04-02 2ca2a09d6215 ("fs: add ksys_close() wrapper; remove in-kernel
 * calls to sys_close()")
 * Kernels v5.11-rc1 onwards have stopped exporting __close_fd, and started
 * exporting close_fd, as of this commit:
 * 2020-12-20 8760c909f54a ("file: Rename __close_fd to close_fd and remove
 * the files parameter")
 */
#if NV_IS_EXPORT_SYMBOL_PRESENT_close_fd
    close_fd(fd);
#elif NV_IS_EXPORT_SYMBOL_PRESENT___close_fd
    __close_fd(current->files, fd);
#else
    extern sysreturn close(int fd);
    close(fd);
#endif
}

static nv_cap_t* nv_cap_alloc(nv_cap_t *parent_cap, const char *name)
{
    nv_cap_t *cap;
    int name_len, path_len;
    int len;

    if (parent_cap == NULL || name == NULL)
    {
        return NULL;
    }

    NV_KMALLOC(cap, sizeof(nv_cap_t));
    if (cap == NULL)
    {
        return NULL;
    }

    name_len = strlen(name);
    path_len = strlen(parent_cap->path);
    len = name_len + path_len + 2;
    NV_KMALLOC(cap->path, len);
    if (cap->path == NULL)
    {
        NV_KFREE(cap, sizeof(nv_cap_t));
        return NULL;
    }

    runtime_memcpy(cap->path, parent_cap->path, path_len);
    cap->path[path_len] = '/';
    runtime_memcpy(cap->path + path_len + 1, name, name_len + 1);

    len = name_len + 1;
    NV_KMALLOC(cap->name, len);
    if (cap->name == NULL)
    {
        NV_KFREE(cap->path, strlen(cap->path) + 1);
        NV_KFREE(cap, sizeof(nv_cap_t));
        return NULL;
    }

    runtime_memcpy(cap->name, name, name_len + 1);

    cap->minor = -1;
    cap->modify = NVreg_ModifyDeviceFiles;

    return cap;
}

static void nv_cap_free(nv_cap_t *cap)
{
    if (cap == NULL)
    {
        return;
    }

    NV_KFREE(cap->path, strlen(cap->path) + 1);
    NV_KFREE(cap->name, strlen(cap->name) + 1);
    NV_KFREE(cap, sizeof(nv_cap_t));
}

nv_cap_t* NV_API_CALL nv_cap_create_file_entry(nv_cap_t *parent_cap,
                                               const char *name, int mode)
{
    nv_cap_t *cap = NULL;
    int minor;

    cap = nv_cap_alloc(parent_cap, name);
    if (cap == NULL)
    {
        return NULL;
    }

    cap->parent = parent_cap->entry;
    cap->permissions = mode;

    minor = nv_cap_find_minor(cap->path);
    if (minor < 0)
    {
        nv_cap_free(cap);
        return NULL;
    }

    cap->minor = minor;

    cap->entry = NULL;
    if (cap->entry == NULL)
    {
        nv_cap_free(cap);
        return NULL;
    }

    return cap;
}

nv_cap_t* NV_API_CALL nv_cap_create_dir_entry(nv_cap_t *parent_cap,
                                              const char *name, int mode)
{
    nv_cap_t *cap = NULL;

    cap = nv_cap_alloc(parent_cap, name);
    if (cap == NULL)
    {
        return NULL;
    }

    cap->parent = parent_cap->entry;
    cap->permissions = mode;
    cap->minor = -1;

    cap->entry = NULL;
    if (cap->entry == NULL)
    {
        nv_cap_free(cap);
        return NULL;
    }

    return cap;
}

nv_cap_t* NV_API_CALL nv_cap_init(const char *path)
{
    nv_cap_t parent_cap;
    nv_cap_t *cap;
    int mode;
    int path_len = strlen(path);
    char *name = NULL;
    char dir[] = "/capabilities";

    if (path == NULL)
    {
        return NULL;
    }

    NV_KMALLOC(name, (path_len + strlen(dir)) + 1);
    if (name == NULL)
    {
        return NULL;
    }

    runtime_memcpy(name, path, path_len);
    runtime_memcpy(name + path_len, dir, sizeof(dir));
    parent_cap.entry = NULL;
    parent_cap.path = "";
    parent_cap.name = "";
    mode = 0;
    cap = nv_cap_create_dir_entry(&parent_cap, name, mode);

    NV_KFREE(name, strlen(name) + 1);
    return cap;
}

void NV_API_CALL nv_cap_destroy_entry(nv_cap_t *cap)
{
    if (WARN_ON(cap == NULL))
    {
        return;
    }

    nv_cap_free(cap);
}

int NV_API_CALL nv_cap_drv_init(void)
{
    nv_cap_tables_init();

    if (g_nv_cap_drv.initialized)
    {
        nv_printf(NV_DBG_ERRORS, "nv-caps-drv is already initialized.\n");
        return -EBUSY;
    }

    g_nv_cap_drv.initialized = NV_TRUE;

    return 0;
}

void NV_API_CALL nv_cap_drv_exit(void)
{
    if (!g_nv_cap_drv.initialized)
    {
        return;
    }

    g_nv_cap_drv.initialized = NV_FALSE;
}
