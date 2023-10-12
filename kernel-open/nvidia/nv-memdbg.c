/*
 * SPDX-FileCopyrightText: Copyright (c) 2017 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "nv-memdbg.h"
#include "nv-nanos.h"

/* track who's allocating memory and print out a list of leaked allocations at
 * teardown.
 */

typedef struct {
    struct rbnode rb_node;
    void *addr;
    NvU64 size;
    NvU32 line;
    const char *file;
} nv_memdbg_node_t;

declare_closure_struct(0, 2, int, memdbg_compare,
                 rbnode, a, rbnode, b);
declare_closure_struct(0, 1, boolean, memdbg_print,
                 rbnode, n);
struct
{
    struct rbtree rb_root;
    NvU64 untracked_bytes;
    NvU64 num_untracked_allocs;
    nv_spinlock_t lock;
    closure_struct(memdbg_compare, compare);
    closure_struct(memdbg_print, print);
} g_nv_memdbg;

define_closure_function(0, 2, int, memdbg_compare,
                 rbnode, a, rbnode, b)
{
    void * sa = ((nv_memdbg_node_t *)a)->addr;
    void * sb = ((nv_memdbg_node_t *)b)->addr;
    return sa == sb ? 0 : (sa < sb ? -1 : 1);
}

define_closure_function(0, 1, boolean, memdbg_print,
                 rbnode, n)
{
    rprintf(" %p", ((nv_memdbg_node_t *)n)->addr);
    return true;
}

void nv_memdbg_init(void)
{
    NV_SPIN_LOCK_INIT(&g_nv_memdbg.lock);
    init_rbtree(&g_nv_memdbg.rb_root, init_closure(&g_nv_memdbg.compare, memdbg_compare),
                init_closure(&g_nv_memdbg.print, memdbg_print));
}

static void nv_memdbg_insert_node(nv_memdbg_node_t *new)
{
    init_rbnode(&new->rb_node);
    rbtree_insert_node(&g_nv_memdbg.rb_root, &new->rb_node);
}

static nv_memdbg_node_t *nv_memdbg_remove_node(void *addr)
{
    nv_memdbg_node_t k = {
        .addr = addr,
    };
    nv_memdbg_node_t *node;

    node = (nv_memdbg_node_t *)rbtree_lookup(&g_nv_memdbg.rb_root, &k.rb_node);
    if (node == INVALID_ADDRESS)
        return 0;
    rbtree_remove_node(&g_nv_memdbg.rb_root, &node->rb_node);
    return node;
}

void nv_memdbg_add(void *addr, NvU64 size, const char *file, int line)
{
    nv_memdbg_node_t *node;
    unsigned long flags;

    WARN_ON(addr == NULL);

    /* If node allocation fails, we can still update the untracked counters */
    node = kmalloc(sizeof(*node),
                   NV_MAY_SLEEP() ? NV_GFP_KERNEL : NV_GFP_ATOMIC);
    if (node)
    {
        node->addr = addr;
        node->size = size;
        node->file = file;
        node->line = line;
    }

    NV_SPIN_LOCK_IRQSAVE(&g_nv_memdbg.lock, flags);

    if (node)
    {
        nv_memdbg_insert_node(node);
    }
    else
    {
        ++g_nv_memdbg.num_untracked_allocs;
        g_nv_memdbg.untracked_bytes += size;
    }

    NV_SPIN_UNLOCK_IRQRESTORE(&g_nv_memdbg.lock, flags);
}

void nv_memdbg_remove(void *addr, NvU64 size, const char *file, int line)
{
    nv_memdbg_node_t *node;
    unsigned long flags;

    NV_SPIN_LOCK_IRQSAVE(&g_nv_memdbg.lock, flags);

    node = nv_memdbg_remove_node(addr);
    if (!node)
    {
        WARN_ON(g_nv_memdbg.num_untracked_allocs == 0);
        WARN_ON(g_nv_memdbg.untracked_bytes < size);
        --g_nv_memdbg.num_untracked_allocs;
        g_nv_memdbg.untracked_bytes -= size;
    }

    NV_SPIN_UNLOCK_IRQRESTORE(&g_nv_memdbg.lock, flags);

    if (node)
    {
        if ((size != 0) && (node->size != size))
        {
            nv_printf(NV_DBG_ERRORS,
                "NVRM: size mismatch on free: %llu != %llu\n",
                size, node->size);
            if (node->file)
            {
                nv_printf(NV_DBG_ERRORS,
                    "NVRM:     allocation: 0x%p @ %s:%d\n",
                    node->addr, node->file, node->line);
            }
            else
            {
                nv_printf(NV_DBG_ERRORS,
                    "NVRM:     allocation: 0x%p\n",
                    node->addr);
            }
            os_dbg_breakpoint();
        }

        kfree(node);
    }
}

void nv_memdbg_exit(void)
{
    nv_memdbg_node_t *node, *next;
    NvU64 leaked_bytes = 0, num_leaked_allocs = 0;

    node = (nv_memdbg_node_t *)rbtree_find_first(&g_nv_memdbg.rb_root);
    if (node != INVALID_ADDRESS)
    {
        nv_printf(NV_DBG_ERRORS,
            "NVRM: list of leaked memory allocations:\n");
    }

    while (node != INVALID_ADDRESS)
    {
        leaked_bytes += node->size;
        ++num_leaked_allocs;

        if (node->file)
        {
            nv_printf(NV_DBG_ERRORS,
                "NVRM:    %llu bytes, 0x%p @ %s:%d\n",
                node->size, node->addr, node->file, node->line);
        }
        else
        {
            nv_printf(NV_DBG_ERRORS,
                "NVRM:    %llu bytes, 0x%p\n",
                node->size, node->addr);
        }

        next = (nv_memdbg_node_t *)rbnode_get_next(&node->rb_node);
        rbtree_remove_node(&g_nv_memdbg.rb_root, &node->rb_node);
        kfree(node);
        node = next;
    }

    /* If we failed to allocate a node at some point, we may have leaked memory
     * even if the tree is empty */
    if (num_leaked_allocs > 0 || g_nv_memdbg.num_untracked_allocs > 0)
    {
        nv_printf(NV_DBG_ERRORS,
            "NVRM: total leaked memory: %llu bytes in %llu allocations\n",
            leaked_bytes + g_nv_memdbg.untracked_bytes,
            num_leaked_allocs + g_nv_memdbg.num_untracked_allocs);

        if (g_nv_memdbg.num_untracked_allocs > 0)
        {
            nv_printf(NV_DBG_ERRORS,
                "NVRM:                      %llu bytes in %llu allocations untracked\n",
                g_nv_memdbg.untracked_bytes, g_nv_memdbg.num_untracked_allocs);
        }
    }
}
