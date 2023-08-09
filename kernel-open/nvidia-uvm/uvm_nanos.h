#ifndef _UVM_NANOS_H
#define _UVM_NANOS_H

#ifndef _KERNEL_H_
#define _KERNEL_H_
#include <net_system_structs.h>
#include <unix_internal.h>
#endif

#include "nvtypes.h"
#include "nv-time.h"
#include "uvm_forward_decl.h"

#define NV_BUILD_MODULE_INSTANCES 0
#include "nv-nanos.h"

#include "nv-kthread-q.h"

#define UVM_THREAD_AFFINITY_SUPPORTED() 0

static inline const struct cpumask *uvm_cpumask_of_node(int node)
{
    return NULL;
}

#define BITS_PER_LONG   64

#define IS_ALIGNED  NV_IS_ALIGNED

#define __read_mostly
#define ____cacheline_aligned_in_smp    __attribute__((aligned(64)))

#define DEFINE_PER_CPU(type, name)  type name
#define get_cpu_var(name)           name
#define put_cpu_var(name)

#define UINT_MAX    (~0U)

#define MKDEV   makedev

#define RB_CLEAR_NODE(n)            (n)->parent_color = u64_from_pointer(n)
#define RB_EMPTY_NODE(n)            ((n)->parent_color == u64_from_pointer(n))
#define rb_entry(ptr, type, member) struct_from_field(ptr, type *, member)
#define rb_first                    rbtree_find_first
#define rb_erase(node, tree)        rbtree_remove_node(tree, node)

#define module_param(name, type, flags)
#define MODULE_PARM_DESC(name, desc)

typedef unsigned long uintptr_t;

#define cancel_delayed_work(dwork)  remove_timer(kernel_timers, dwork, 0)
#define cancel_delayed_work_sync    cancel_delayed_work

#define UVM_IS_CONFIG_HMM() 0

#define UVM_CAN_USE_MMU_NOTIFIERS() 0

#if !defined(VM_RESERVED)
#define VM_RESERVED    0x00000000
#endif
#if !defined(VM_DONTEXPAND)
#define VM_DONTEXPAND  0x00000000
#endif
#if !defined(VM_DONTDUMP)
#define VM_DONTDUMP    0x00000000
#endif
#if !defined(VM_MIXEDMAP)
#define VM_MIXEDMAP    0x00000000
#endif

#define NVIDIA_UVM_PRETTY_PRINTING_PREFIX "nvidia-uvm: "
#define pr_fmt(fmt) NVIDIA_UVM_PRETTY_PRINTING_PREFIX fmt

#define UVM_NO_PRINT(fmt, ...)           \
    do {                                 \
        if (0)                           \
            rprintf(fmt, ##__VA_ARGS__); \
    } while (0)

#define printk_ratelimited UVM_NO_PRINT
#define pr_debug_ratelimited UVM_NO_PRINT

// Develop builds define DEBUG but enable optimization
#if defined(DEBUG) && !defined(NVIDIA_UVM_DEVELOP)
  // Wrappers for functions not building correctly without optimizations on,
  // implemented in uvm_debug_optimized.c. Notably the file is only built for
  // debug builds, not develop or release builds.

  int nv_atomic_xchg(atomic_t *val, int new);

  int nv_atomic_cmpxchg(atomic_t *val, int old, int new);

  long nv_atomic_long_cmpxchg(atomic_long_t *val, long old, long new);

#else
  #define nv_atomic_xchg            atomic_swap_32
  #define nv_atomic_cmpxchg         __sync_val_compare_and_swap
  #define nv_atomic_long_cmpxchg    __sync_val_compare_and_swap
#endif

#ifndef NV_ALIGN_DOWN
#define NV_ALIGN_DOWN(v,g) ((v) & ~((g) - 1))
#endif

#define DIV_ROUND_UP(n, d)  (((n) + (d) - 1) / (d))

#define roundup(x, y) ({                \
    typeof(y) __y = y;                  \
    (((x) + (__y - 1)) / __y) * __y;    \
})

static inline u64 roundup_pow_of_two(u64 val)
{
    return U64_FROM_BIT(find_order(val));
}

static inline u64 rounddown_pow_of_two(u64 val)
{
    return U64_FROM_BIT(msb(val));
}

static inline uint64_t NV_DIV64(uint64_t dividend, uint64_t divisor, uint64_t *remainder)
{
    *remainder = dividend % divisor;
    return dividend / divisor;
}

static inline NvU64 NV_GETTIME(void)
{
    struct timespec64 tm;

    ktime_get_real_ts64(&tm);
    return (NvU64) timespec64_to_ns(&tm);
}

static inline int NV_ILOG2_U32(u32 n)
{
    return n ? 31 - __builtin_clz(n) : -1;
}
static inline int NV_ILOG2_U64(u64 n)
{
    return msb(n);
}
#define ilog2(n) (              \
    __builtin_constant_p(n) ?   \
    ((n) < 2 ? 0 :              \
     63 - __builtin_clzll(n)) : \
    (sizeof(n) <= 4) ?          \
    NV_ILOG2_U32(n) :           \
    NV_ILOG2_U64(n)             \
)

#define order_base_2(n) ((n) > 1 ? ilog2((n) - 1) + 1 : 0)

#define __fls   msb

static inline int __ffs(u32 n)
{
    return n ? (__builtin_ffs(n) - 1) : -1;
}

static inline __attribute__((const)) boolean is_power_of_2(unsigned long n)
{
    return (n != 0 && ((n & (n - 1)) == 0));
}

#define DECLARE_BITMAP(name, nbits) unsigned long name[((nbits) + 63) / 64]

static inline unsigned long find_next_bit(const unsigned long *addr, u64 nbits, u64 start)
{
    u64 word_offset = start >> 6;
    u64 bit_offset = start & MASK(6);
    for (; start < nbits; word_offset++, bit_offset = 0) {
        const unsigned long *p = addr + word_offset;
        u64 w = *p;
        if (bit_offset > 0)
            w &= ~MASK(bit_offset);
        if (nbits - start < 64 - bit_offset)
            w &= MASK(bit_offset + nbits - start);
        u64 bit = lsb(w);
        if (bit != INVALID_PHYSICAL)
            return (word_offset << 6) + bit;
        start += 64;
    }
    return nbits;
}

static inline unsigned long find_next_zero_bit(const unsigned long *addr, u64 nbits, u64 start)
{
    u64 word_offset = start >> 6;
    u64 bit_offset = start & MASK(6);
    for (; start < nbits; word_offset++, bit_offset = 0) {
        const unsigned long *p = addr + word_offset;
        u64 w = *p;
        if (bit_offset > 0)
            w |= MASK(bit_offset);
        if (nbits - start < 64 - bit_offset)
            w |= ~MASK(bit_offset + nbits - start);
        u64 bit = lsb(~w);
        if (bit != INVALID_PHYSICAL)
            return (word_offset << 6) + bit;
        start += 64;
    }
    return nbits;
}

#define find_first_bit(addr, nbits)         find_next_bit(addr, nbits, 0)
#define find_first_zero_bit(addr, nbits)    find_next_zero_bit(addr, nbits, 0)

static inline boolean __test_and_clear_bit(u64 bit, unsigned long *addr)
{
    u64 mask = U64_FROM_BIT(bit & 0x3f);
    unsigned long *p = addr + (bit >> 6);
    unsigned long old = *p;

    *p &= ~mask;
    return (old & mask) != 0;
}

#define for_each_set_bit(bit, addr, size)                   \
    for ((bit) = find_first_bit((addr), (size));            \
        (bit) < (size);                                     \
        (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_set_bit_from(bit, addr, size)              \
    for ((bit) = find_next_bit((addr), (size), (bit));      \
         (bit) < (size);                                    \
         (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size)                     \
    for ((bit) = find_first_zero_bit((addr), (size));           \
         (bit) < (size);                                        \
         (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit_from(bit, addr, size)                \
    for ((bit) = find_next_zero_bit((addr), (size), (bit));     \
         (bit) < (size);                                        \
         (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

static inline void bitmap_set_bits(unsigned long *map, unsigned int start, int len)
{
    unsigned int index = start;
    for_each_clear_bit_from(index, map, start + len)
        __set_bit(index, map);
}
#define bitmap_set  bitmap_set_bits

static inline void bitmap_clear(unsigned long *map, unsigned int start, int len)
{
    unsigned int index = start;
    for_each_set_bit_from(index, map, start + len)
        __clear_bit(index, map);
}

static inline void bitmap_zero(unsigned long *map, unsigned int nbits)
{
    zero(map, (nbits + 7) / 8);
}

static inline void bitmap_fill(unsigned long *map, unsigned int nbits)
{
    runtime_memset((void *)map, 0xff, (nbits + 7) / 8);
}

static inline boolean bitmap_empty(const unsigned long *map, unsigned int nbits)
{
    return find_first_bit(map, nbits) == nbits;
}

static inline boolean bitmap_full(const unsigned long *map, unsigned int nbits)
{
    return find_first_zero_bit(map, nbits) == nbits;
}

static inline void bitmap_cpy(unsigned long *dst, const unsigned long *src, unsigned int nbits)
{
    runtime_memcpy(dst, src, (nbits + 63) / 64);
}
#define bitmap_copy  bitmap_cpy

static inline void bitmap_complement(unsigned long *dst, const unsigned long *src,
                                     unsigned int nbits)
{
    unsigned int words = (nbits + 63) / 64;

    for (unsigned int i = 0; i < words; i++)
        *dst++ = ~(*src++);
}

static inline void bitmap_shift_right(unsigned long *dst, const unsigned long *src,
                                     unsigned int shift, unsigned int nbits)
{
    unsigned int words = (nbits + 63) / 64;
    unsigned int offset = shift >> 6;
    shift &= 0x3f;
    u64 rem = 0;

    for (unsigned int i = 0; i < offset; i++)
        *dst++ = 0;
    words -= offset;
    for (unsigned int i = 0; i < words; i++) {
        *dst++ = rem | ((*src) >> shift);
        rem = (*src++) << (64 - shift);
    }
}

static inline void bitmap_shift_left(unsigned long *dst, const unsigned long *src,
                                     unsigned int shift, unsigned int nbits)
{
    unsigned int words = (nbits + 63) / 64;
    unsigned int offset = shift >> 6;
    shift &= 0x3f;
    u64 rem = 0;

    dst += words;
    for (unsigned int i = 0; i < offset; i++)
        *(--dst) = 0;
    words -= offset;
    src += words;
    for (unsigned int i = 0; i < words; i++) {
        *(--dst) = rem | ((*--src) << shift);
        rem = (*src) >> (64 - shift);
    }
}

static inline boolean bitmap_and(unsigned long *dst, const unsigned long *src1,
                                 const unsigned long *src2, unsigned int nbits)
{
    unsigned long result = 0;

    while (nbits >= 64) {
        result |= (*(dst++) = *(src1++) & *(src2++));
        nbits -= 64;
    }
    if (nbits)
        result |= (*dst = *src1 & *src2 & MASK(nbits));
    return (result != 0);
}

static inline void bitmap_or(unsigned long *dst, const unsigned long *src1,
                             const unsigned long *src2, unsigned int nbits)
{
    while (nbits > 0) {
        *(dst++) = *(src1++) | *(src2++);
        nbits = (nbits >= 64) ? (nbits - 64) : 0;;
    }
}

static inline boolean bitmap_andnot(unsigned long *dst, const unsigned long *src1,
                                    const unsigned long *src2, unsigned int nbits)
{
    unsigned long result = 0;

    while (nbits >= 64) {
        result |= (*(dst++) = *(src1++) & ~(*(src2++)));
        nbits -= 64;
    }
    if (nbits)
        result |= (*dst = *src1 & ~(*src2) & MASK(nbits));
    return (result != 0);
}

static inline void bitmap_xor(unsigned long *dst, const unsigned long *src1,
                              const unsigned long *src2, unsigned int nbits)
{
    while (nbits > 0) {
        *(dst++) = *(src1++) ^ *(src2++);
        nbits = (nbits >= 64) ? (nbits - 64) : 0;;
    }
}

static inline boolean bitmap_equal(const unsigned long *src1,
                                   const unsigned long *src2,
                                   unsigned int nbits)
{
    while (nbits >= 64) {
        if (*(src1++) != *(src2++))
            return false;
        nbits -= 64;
    }
    if (nbits)
        return ((*src1 & MASK(nbits)) == (*src2 & MASK(nbits)));
    return true;
}

static inline boolean bitmap_subset(const unsigned long *src1,
                                    const unsigned long *src2,
                                    unsigned int nbits)
{
    while (nbits >= 64) {
        if (*(src1++) & ~(*(src2++)))
            return false;
        nbits -= 64;
    }
    if (nbits)
        return !((*src1 & MASK(nbits)) & ~(*src2 & MASK(nbits)));
    return true;
}

static inline boolean bitmap_intersects(const unsigned long *src1,
                                        const unsigned long *src2,
                                        unsigned int nbits)
{
    while (nbits >= 64) {
        if (*(src1++) & *(src2++))
            return true;
        nbits -= 64;
    }
    if (nbits)
        return (*src1 & *src2 & MASK(nbits)) != 0;
    return false;
}


static inline int bitmap_weight(const unsigned long *src, unsigned int nbits)
{
    int w = 0;

    while (nbits >= 64) {
        unsigned long map = *src++;

        for (unsigned int i = 0; i < 64; i++)
            if (map & U64_FROM_BIT(i))
                w++;
        nbits -= 64;
    }
    if (nbits) {
        unsigned long map = *src;

        for (unsigned int i = 0; i < nbits; i++)
            if (map & U64_FROM_BIT(i))
                w++;
    }
    return w;
}

static inline u64 hash_64(u64 input)
{
    return (input ^ 0xcbf29ce484222325) * 1099511628211;
}

static inline unsigned int hweight32(u32 val)
{
    unsigned int w = 0;

    for (unsigned int i = 0; i < 32; i++)
        if (val & U64_FROM_BIT(i))
            w++;
    return w;
}

static inline unsigned int hweight_long(long val)
{
    unsigned int w = 0;

    for (unsigned int i = 0; i < 64; i++)
        if (val & U64_FROM_BIT(i))
            w++;
    return w;
}

static inline boolean sort(void **elems, u64 num, boolean(*sort_fn)(void *, void *))
{
    pqueue pq = allocate_pqueue(heap_locked(get_kernel_heaps()), sort_fn);
    if (pq == INVALID_ADDRESS)
        return false;
    for (u64 i = 0; i < num; i++)
        pqueue_insert(pq, elems[i]);
    for (u64 i = 0; i < num; i++)
        elems[i] = pqueue_pop(pq);
    deallocate_pqueue(pq);
    return true;
}

#define mb()    memory_barrier()
#define rmb()   read_barrier()
#define wmb()   write_barrier()

#define PAGE_ALIGNED(addr) (((addr) & (PAGESIZE - 1)) == 0)

#define KMEM_CACHE_CREATE(size)    ({                                       \
    kernel_heaps kh = get_kernel_heaps();                                   \
    heap meta = (heap)heap_locked(kh);                                      \
    heap parent = (heap)heap_linear_backed(kh);                             \
    u64 page_size = (size < 32) ? PAGESIZE : PAGESIZE_2M;                   \
    heap h = (heap)allocate_objcache(meta, parent, size, page_size, true);  \
    if (h == INVALID_ADDRESS) h = 0;                                        \
    h;                                                                      \
})

static inline heap nv_kmem_cache_create(const char *name, u64 size, u64 align)
{
    return KMEM_CACHE_CREATE(size);
}

#define NV_KMEM_CACHE_CREATE(name, type)    KMEM_CACHE_CREATE(sizeof(type))
static inline void *kmem_cache_alloc(heap cache, int flags) {
    void *ptr = allocate(cache, cache->pagesize);
    if (ptr != INVALID_ADDRESS)
        return ptr;
    return 0;
}
static inline void *kmem_cache_zalloc(heap cache, int flags) {
    void *ptr = allocate(cache, cache->pagesize);
    if (ptr != INVALID_ADDRESS) {
        zero(ptr, cache->pagesize);
        return ptr;
    }
    return 0;
}
#define nv_kmem_cache_zalloc    kmem_cache_zalloc
#define kmem_cache_free(c, p)   deallocate(c, p, (c)->pagesize)
#define kmem_cache_destroy(c)   destroy_heap(c)

#define SetPageDirty(p)
#define ClearPageDirty(p)
#define set_page_dirty(p)
#define put_page(p)

#define kbasename(name) (name)

#define UVM_WAIT_ON_BIT_LOCK(word, bit, mode)   ({  \
    u64 *p = ((u64 *)(word)) + ((bit) >> 6);        \
    u64 mask = (bit) & MASK(6);                     \
    while (atomic_test_and_set_bit(p, mask))        \
        kern_pause();                               \
     0; })

static inline void set_bit(u64 bit, unsigned long *addr)
{
    u64 *p = (u64 *)addr + (bit >> 6);

    atomic_set_bit(p, bit & 0x3f);
}

static inline void clear_bit(u64 bit, unsigned long *addr)
{
    u64 *p = (u64 *)addr + (bit >> 6);

    atomic_clear_bit(p, bit & 0x3f);
}

#define clear_bit_unlock    clear_bit

static inline boolean test_and_set_bit(u64 bit, unsigned long *addr)
{
    u64 *p = (u64 *)addr + (bit >> 6);

    return atomic_test_and_set_bit(p, bit & 0x3f);
}

static inline boolean test_and_clear_bit(u64 bit, unsigned long *addr)
{
    u64 *p = (u64 *)addr + (bit >> 6);

    return atomic_test_and_clear_bit(p, bit & 0x3f);
}

static inline void wake_up_bit(void *word, int bit)
{
}

typedef struct uvm_fd {
    file f;
    uvm_va_space_t *va_space;
    closure_struct(fdesc_ioctl, ioctl);
    closure_struct(fdesc_mmap, mmap);
    closure_struct(fdesc_close, close);
} *uvm_fd;

typedef struct
{
    struct mem_cgroup *new_memcg;
    struct mem_cgroup *old_memcg;
} uvm_memcg_context_t;

#define UVM_CGROUP_ACCOUNTING_SUPPORTED() 0

static inline void uvm_memcg_context_start(uvm_memcg_context_t *context)
{
}

static inline void uvm_memcg_context_end(uvm_memcg_context_t *context)
{
}

#endif // _UVM_NANOS_H
