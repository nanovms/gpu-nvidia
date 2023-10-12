/*
 * SPDX-FileCopyrightText: Copyright (c) 2016 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "nv-kthread-q.h"
#include "nv-list-helpers.h"

#if defined(NV_LINUX_BUG_H_PRESENT)
    #include <linux/bug.h>
#endif

// Today's implementation is a little simpler and more limited than the
// API description allows for in nv-kthread-q.h. Details include:
//
// 1. Each nv_kthread_q instance is a first-in, first-out queue.
//
// 2. Each nv_kthread_q instance is serviced by exactly one kthread.
//
// You can create any number of queues, each of which gets its own
// named kernel thread (kthread). You can then insert arbitrary functions
// into the queue, and those functions will be run in the context of the
// queue's kthread.

#ifndef WARN
    // Only *really* old kernels (2.6.9) end up here. Just use a simple printk
    // to implement this, because such kernels won't be supported much longer.
    #define WARN(condition, format...) ({                    \
        int __ret_warn_on = !!(condition);                   \
        if (unlikely(__ret_warn_on))                         \
            printk(KERN_ERR format);                         \
        unlikely(__ret_warn_on);                             \
    })
#endif

#define NVQ_WARN(fmt, ...)                                   \
    do {                                                     \
        if (in_interrupt()) {                                \
            WARN(1, "nv_kthread_q: [in interrupt]: " fmt,    \
            ##__VA_ARGS__);                                  \
        }                                                    \
        else {                                               \
            WARN(1, "nv_kthread_q: task: %s: " fmt,          \
                 current->name,                              \
                 ##__VA_ARGS__);                             \
        }                                                    \
    } while (0)

static int _main_loop(void *args)
{
    nv_kthread_q_t *q = (nv_kthread_q_t *)args;
    nv_kthread_q_item_t *q_item = NULL;
    unsigned long flags;

    while (1) {
        // Normally this thread is never interrupted. However,
        // down_interruptible (instead of down) is called here,
        // in order to avoid being classified as a potentially
        // hung task, by the kernel watchdog.
        while (down_interruptible(&q->q_sem))
            NVQ_WARN("Interrupted during semaphore wait\n");

        if (atomic_read(&q->main_loop_should_exit))
            break;

        spin_lock_irqsave(&q->q_lock, flags);

        // The q_sem semaphore prevents us from getting here unless there is
        // at least one item in the list, so an empty list indicates a bug.
        if (unlikely(list_empty(&q->q_list_head))) {
            spin_unlock_irqrestore(&q->q_lock, flags);
            NVQ_WARN("_main_loop: Empty queue: q: 0x%p\n", q);
            continue;
        }

        // Consume one item from the queue
        q_item = list_first_entry(&q->q_list_head,
                                   nv_kthread_q_item_t,
                                   q_list_node);

        list_del_init(&q_item->q_list_node);

        spin_unlock_irqrestore(&q->q_lock, flags);

        // Run the item
        q_item->function_to_run(q_item->function_args);

        // Make debugging a little simpler by clearing this between runs:
        q_item = NULL;
    }

    q->ctx = NULL;
    kern_yield();
}

void nv_kthread_q_stop(nv_kthread_q_t *q)
{
    // check if queue has been properly initialized
    if (unlikely(!q->ctx))
        return;

    nv_kthread_q_flush(q);

    // If this assertion fires, then a caller likely either broke the API rules,
    // by adding items after calling nv_kthread_q_stop, or possibly messed up
    // with inadequate flushing of self-rescheduling q_items.
    if (unlikely(!list_empty(&q->q_list_head)))
        NVQ_WARN("list not empty after flushing\n");

    if (likely(!atomic_read(&q->main_loop_should_exit))) {

        atomic_set(&q->main_loop_should_exit, 1);

        // Wake up the kthread so that it can see that it needs to stop:
        up(&q->q_sem);
    }
}

int nv_kthread_q_init_on_node(nv_kthread_q_t *q, const char *q_name, int preferred_node)
{
    u64 *f;

    memset(q, 0, sizeof(*q));

    INIT_LIST_HEAD(&q->q_list_head);
    spin_lock_init(&q->q_lock);
    sema_init(&q->q_sem, 0);

    if (preferred_node == NV_KTHREAD_NO_NODE) {
        q->ctx = (context)allocate_kernel_context(current_cpu());
    }
    else {
        return -ENOTSUPP;
    }

    if (q->ctx == INVALID_ADDRESS) {
        int err = -ENOMEM;

        // Clear q_kthread before returning so that nv_kthread_q_stop() can be
        // safely called on it making error handling easier.
        q->ctx = NULL;

        return err;
    }

    f = q->ctx->frame;
#if defined(NVCPU_X86_64)
    f[FRAME_RIP] = u64_from_pointer(_main_loop);
    f[FRAME_RDI] = u64_from_pointer(q);
    f[FRAME_CS] = 0x8;
    f[FRAME_SS] = 0x0;
#elif defined(NVCPU_AARCH64)
    f[FRAME_ELR] = u64_from_pointer(_main_loop);
    f[FRAME_X0] = u64_from_pointer(q);
#endif
    frame_reset_stack(f);
    f[FRAME_FULL] = true;
    context_schedule_return(q->ctx);

    return 0;
}

// Returns true (non-zero) if the item was actually scheduled, and false if the
// item was already pending in a queue.
static int _raw_q_schedule(nv_kthread_q_t *q, nv_kthread_q_item_t *q_item)
{
    unsigned long flags;
    int ret = 1;

    spin_lock_irqsave(&q->q_lock, flags);

    if (likely(list_empty(&q_item->q_list_node)))
        list_add_tail(&q_item->q_list_node, &q->q_list_head);
    else
        ret = 0;

    spin_unlock_irqrestore(&q->q_lock, flags);

    if (likely(ret))
        up(&q->q_sem);

    return ret;
}

void nv_kthread_q_item_init(nv_kthread_q_item_t *q_item,
                            nv_q_func_t function_to_run,
                            void *function_args)
{
    INIT_LIST_HEAD(&q_item->q_list_node);
    q_item->function_to_run = function_to_run;
    q_item->function_args   = function_args;
}

// Returns true (non-zero) if the q_item got scheduled, false otherwise.
int nv_kthread_q_schedule_q_item(nv_kthread_q_t *q,
                                 nv_kthread_q_item_t *q_item)
{
    if (unlikely(atomic_read(&q->main_loop_should_exit))) {
        NVQ_WARN("Not allowed: nv_kthread_q_schedule_q_item was "
                   "called with a non-alive q: 0x%p\n", q);
        return 0;
    }

    return _raw_q_schedule(q, q_item);
}

static void _q_flush_function(void *args)
{
    boolean *done = args;
    *done = true;
}


static void _raw_q_flush(nv_kthread_q_t *q)
{
    nv_kthread_q_item_t q_item;
    volatile boolean done = false;

    nv_kthread_q_item_init(&q_item, _q_flush_function, (void *)&done);

    _raw_q_schedule(q, &q_item);

    // Wait for the flush item to run. Once it has run, then all of the
    // previously queued items in front of it will have run, so that means
    // the flush is complete.
    while (!done)
        os_schedule();
}

void nv_kthread_q_flush(nv_kthread_q_t *q)
{
    if (unlikely(atomic_read(&q->main_loop_should_exit))) {
        NVQ_WARN("Not allowed: nv_kthread_q_flush was called after "
                   "nv_kthread_q_stop. q: 0x%p\n", q);
        return;
    }

    // This 2x flush is not a typing mistake. The queue really does have to be
    // flushed twice, in order to take care of the case of a q_item that
    // reschedules itself.
    _raw_q_flush(q);
    _raw_q_flush(q);
}
