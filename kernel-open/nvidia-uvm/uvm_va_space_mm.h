/*******************************************************************************
    Copyright (c) 2018-2021 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#ifndef __UVM_VA_SPACE_MM_H__
#define __UVM_VA_SPACE_MM_H__

#include "uvm_nanos.h"
#include "uvm_forward_decl.h"
#include "uvm_lock.h"
#include "uvm_test_ioctl.h"
#include "nv-kref.h"

struct uvm_va_space_mm_struct
{
#if UVM_CAN_USE_MMU_NOTIFIERS()
    struct mmu_notifier mmu_notifier;
#endif

    // Lock protecting the alive and retained_count fields.
    uvm_spinlock_t lock;

    // Whether the mm is usable. uvm_va_space_mm_register() marks the mm as
    // alive and uvm_va_space_mm_shutdown() marks it as dead.
    bool alive;

    // Refcount for uvm_va_space_mm_retain()/uvm_va_space_mm_release()
    NvU32 retained_count;

    // State which is only injected by test ioctls
    struct
    {
        // Whether uvm_va_space_mm_shutdown() should do a timed wait for other
        // threads to arrive.
        bool delay_shutdown;

        bool verbose;

        // Number of threads which have called uvm_va_space_mm_shutdown(). Only
        // used when delay_shutdown is true.
        atomic_t num_mm_shutdown_threads;
    } test;
};

// Whether the system can support creating an association between a VA space and
// an mm.
bool uvm_va_space_mm_enabled_system(void);

// Whether this VA space is associated with an mm. This must not be called
// before uvm_va_space_initialize().
bool uvm_va_space_mm_enabled(uvm_va_space_t *va_space);

// Registers current->mm with the va_space. A reference is taken on the mm,
// meaning that until uvm_va_space_mm_unregister() is called the mm will remain
// a valid object in memory (mm_count), but is not guaranteed to remain alive
// (mm_users).
//
// Use uvm_va_space_mm_retain() to retrieve the mm.
//
// Locking: mmap_lock and the VA space lock must both be held for write.
NV_STATUS uvm_va_space_mm_register(uvm_va_space_t *va_space);

// De-associate the mm from the va_space. This function won't return until all
// in-flight retainers have called uvm_va_space_mm_release(). Subsequent calls
// to uvm_va_space_mm_retain() will return NULL.
//
// This function may invoke uvm_va_space_mm_shutdown() so the caller must not
// hold either mmap_lock or the VA space lock. Since this API must provide the
// same guarantees as uvm_va_space_mm_shutdown(), the caller must also guarantee
// prior to calling this function that all GPUs in this VA space have stopped
// making accesses under this mm and will not be able to start again under that
// VA space.
//
// Locking: This function may take both mmap_lock and the VA space lock.
void uvm_va_space_mm_unregister(uvm_va_space_t *va_space);

NV_STATUS uvm_test_va_space_mm_retain(UVM_TEST_VA_SPACE_MM_RETAIN_PARAMS *params, struct file *filp);
NV_STATUS uvm_test_va_space_mm_delay_shutdown(UVM_TEST_VA_SPACE_MM_DELAY_SHUTDOWN_PARAMS *params, struct file *filp);

#endif // __UVM_VA_SPACE_MM_H__
