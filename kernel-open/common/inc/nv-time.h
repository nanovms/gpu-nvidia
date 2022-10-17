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

#ifndef __NV_TIME_H__
#define __NV_TIME_H__

#include "conftest.h"

#include <nvstatus.h>

#define NV_MAX_ISR_DELAY_US           20000
#define NV_MAX_ISR_DELAY_MS           (NV_MAX_ISR_DELAY_US / 1000)
#define NV_NSECS_TO_JIFFIES(nsec)     ((nsec) * HZ / 1000000000)

#if !defined(NV_TIMESPEC64_PRESENT)
struct timespec64 {
    s64 tv_sec;
    long  tv_nsec;
};
#endif

#if !defined(NV_KTIME_GET_RAW_TS64_PRESENT)
static inline void ktime_get_raw_ts64(struct timespec64 *ts64)
{
    struct timespec ts;
    timespec_from_time(&ts, kern_now(CLOCK_ID_MONOTONIC_RAW));
    ts64->tv_sec = ts.tv_sec;
    ts64->tv_nsec = ts.tv_nsec;
}
#endif

#if !defined(NV_KTIME_GET_REAL_TS64_PRESENT)
static inline void ktime_get_real_ts64(struct timespec64 *ts64)
{
    struct timespec ts;
    timespec_from_time(&ts, kern_now(CLOCK_ID_REALTIME));
    ts64->tv_sec = ts.tv_sec;
    ts64->tv_nsec = ts.tv_nsec;
}
#endif

static NvBool nv_timer_less_than
(
    const struct timespec64 *a,
    const struct timespec64 *b
)
{
    return (a->tv_sec == b->tv_sec) ? (a->tv_nsec < b->tv_nsec)
                                    : (a->tv_sec < b->tv_sec);
}

#if !defined(NV_TIMESPEC64_PRESENT)
static inline struct timespec64 timespec64_add
(
    const struct timespec64    a,
    const struct timespec64    b
)
{
    struct timespec64 result;

    result.tv_sec = a.tv_sec + b.tv_sec;
    result.tv_nsec = a.tv_nsec + b.tv_nsec;
    while (result.tv_nsec >= BILLION)
    {
        ++result.tv_sec;
        result.tv_nsec -= BILLION;
    }
    return result;
}

static inline struct timespec64  timespec64_sub
(
    const struct timespec64    a,
    const struct timespec64    b
)
{
    struct timespec64 result;

    result.tv_sec = a.tv_sec - b.tv_sec;
    result.tv_nsec = a.tv_nsec - b.tv_nsec;
    while (result.tv_nsec < 0)
    {
        --(result.tv_sec);
        result.tv_nsec += BILLION;
    }
    return result;
}

static inline s64 timespec64_to_ns(struct timespec64 *ts)
{
    return ((s64) ts->tv_sec *  BILLION) + ts->tv_nsec;
}
#endif

static inline NvU64 nv_ktime_get_raw_ns(void)
{
    return nsec_from_timestamp(kern_now(CLOCK_ID_MONOTONIC_RAW));
}

// #define NV_CHECK_DELAY_ACCURACY 1

/*
 * It is generally a bad idea to use udelay() to wait for more than
 * a few milliseconds. Since the caller is most likely not aware of
 * this, we use mdelay() for any full millisecond to be safe.
 */
static inline NV_STATUS nv_sleep_us(unsigned int us)
{
#ifdef NV_CHECK_DELAY_ACCURACY
    struct timespec64 tm1, tm2, tm_diff;

    ktime_get_raw_ts64(&tm1);
#endif

    if (in_interrupt() && (us > NV_MAX_ISR_DELAY_US))
        return NV_ERR_GENERIC;

    kernel_delay(microseconds(us));

#ifdef NV_CHECK_DELAY_ACCURACY
    ktime_get_raw_ts64(&tm2);
    tm_diff = timespec64_sub(tm2, tm1);
    pr_info("NVRM: delay of %d usec results in actual delay of 0x%llu nsec\n",
             us, timespec64_to_ns(&tm_diff));
#endif
    return NV_OK;
}

/*
 * Sleep for specified milliseconds. Yields the CPU to scheduler.
 *
 * On Linux, a jiffie represents the time passed in between two timer
 * interrupts. The number of jiffies per second (HZ) varies across the
 * supported platforms. On i386, where HZ is 100, a timer interrupt is
 * generated every 10ms. NV_MSECS_TO_JIFFIES should be accurate independent of
 * the actual value of HZ; any partial jiffies will be 'floor'ed, the
 * remainder will be accounted for with mdelay().
 */
static inline NV_STATUS nv_sleep_ms(unsigned int ms)
{
    if (in_interrupt() && (ms > NV_MAX_ISR_DELAY_MS))
    {
        return NV_ERR_GENERIC;
    }

    kernel_delay(milliseconds(ms));
    return NV_OK;
}

#endif // __NV_TIME_H__
