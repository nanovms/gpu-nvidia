#ifndef _NV_NANOS_H_
#define _NV_NANOS_H_

#ifndef _KERNEL_H_
#define _KERNEL_H_
#include <unix_internal.h>
#endif

#ifndef NULL
#define NULL    0
#endif

#define INT_MAX     0x7FFFFFFFU
#define UINT_MAX    (~0U)
#define ULLONG_MAX  (~0ULL)

#define NV_MAX_REGISTRY_KEYS_LENGTH 512

typedef s32 int32_t;
typedef u8 uint8_t;
typedef u32 uint32_t;
typedef u64 uint64_t;
typedef s64 ssize_t;
typedef u64 size_t;

typedef boolean bool;

typedef u32 atomic_t;
typedef u64 atomic64_t;
typedef u64 atomic_long_t;

typedef u64 dma_addr_t;

typedef pageflags pgprot_t;

typedef u64 dev_t;

#include "nv.h"
#include "nv-ioctl-numa.h"

#include "nv-list-helpers.h"
#include "nv-pgprot.h"
#include "nv-mm.h"
#include "os-interface.h"
#include "nv-memdbg.h"
#include "nv-timer.h"

#define NV_CURRENT_EUID()   0

#define NV_CONTROL_DEVICE_MINOR       255

#define NV_IS_SUSER()   NV_TRUE

#define PAGE_SIZE   PAGESIZE
#define PAGE_MASK   PAGEMASK
#define PAGE_SHIFT  PAGELOG

#define NV_PAGE_MASK    (~(PAGESIZE - 1))

#define ENOTSUPP    524

#define ARRAY_SIZE  _countof

#define container_of(var, type, field)  struct_from_field(var, type *, field)

typedef struct nv_dma_submap_s {
    NvU32 page_count;
    NvU32 sg_map_count;
    struct sg_list sgt;
    NvBool imported;
} nv_dma_submap_t;

typedef struct nv_dma_map_s {
    NvU64 *pages;
    NvU64 page_count;
    NvBool contiguous;
    NvU32 cache_type;
    sg_list import_sgt;

    union
    {
        struct
        {
            NvU32 submap_count;
            nv_dma_submap_t *submaps;
        } discontig;

        struct
        {
            NvU64 dma_addr;
        } contig;
    } mapping;

    struct device *dev;
} nv_dma_map_t;

#define NV_FOR_EACH_DMA_SUBMAP(dm, sm, i)               \
    for (i = 0, sm = &dm->mapping.discontig.submaps[0]; \
         i < dm->mapping.discontig.submap_count;        \
         i++, sm = &dm->mapping.discontig.submaps[i])

#define NV_DMA_SUBMAP_MAX_PAGES           ((NvU32)(NV_U32_MAX >> PAGELOG))
#define NV_DMA_SUBMAP_IDX_TO_PAGE_IDX(s)  (s * NV_DMA_SUBMAP_MAX_PAGES)

static inline NV_STATUS NV_ALLOC_DMA_SUBMAP_SCATTERLIST(nv_dma_map_t *dm, nv_dma_submap_t *sm,
                                                        NvU32 i)
{
    heap h = heap_locked(get_kernel_heaps());
    sm->sgt.b = allocate_buffer(h, sizeof(struct sg_buf) * sm->page_count);
    if (sm->sgt.b == INVALID_ADDRESS)
        return NV_ERR_OPERATING_SYSTEM;
    sm->sgt.count = 0;
#if defined(NV_DOM0_KERNEL_PRESENT)
    for (NvU32 i = 0; i < sm->page_count; i++)
        sg_list_tail_add(&sm->sgt, PAGESIZE);
#else
    NvU64 page_idx = NV_DMA_SUBMAP_IDX_TO_PAGE_IDX(i);
    for (NvU32 i = 0; i < sm->page_count; i++) {
        sg_buf sgb = sg_list_tail_add(&sm->sgt, PAGE_SIZE);
        sgb->buf = pointer_from_u64(dm->pages[page_idx++]);
        sgb->size = PAGE_SIZE;
        sgb->offset = 0;
        sgb->refcount = 0;
    }
#endif
    return NV_OK;
}

typedef struct nv_ibmnpu_info nv_ibmnpu_info_t;

typedef enum
{
    NV_DEV_STACK_TIMER,
    NV_DEV_STACK_ISR,
    NV_DEV_STACK_ISR_BH,
    NV_DEV_STACK_ISR_BH_UNLOCKED,
    NV_DEV_STACK_GPU_WAKEUP,
    NV_DEV_STACK_COUNT
} nvidia_nanos_dev_stack_t;

#define spin_lock_irqsave(lock, flags)      flags = spin_lock_irq(lock)
#define spin_unlock_irqrestore(lock, flags) spin_unlock_irq(lock, flags)

typedef struct spinlock spinlock_t;

struct semaphore {
    u64 value;
    struct list waiters;
    struct spinlock lock;
};

static inline void down(struct semaphore *sema)
{
    context ctx;
    boolean wait;

begin:
    spin_lock(&sema->lock);
    if (sema->value > 0) {
        sema->value--;
        wait = false;
    } else {
        ctx = get_current_context(current_cpu());
        list_push_back(&sema->waiters, &ctx->mutex_l);
        wait = true;
    }
    spin_unlock(&sema->lock);
    if (wait) {
        context_pre_suspend(ctx);
        context_suspend();
        goto begin;
    }
}

#define down_interruptible(sema)    ({down(sema); 0;})

static inline int down_trylock(struct semaphore *sema)
{
    boolean acquired;

    spin_lock(&sema->lock);
    if (sema->value > 0) {
        sema->value--;
        acquired = true;
    } else {
        acquired = false;
    }
    spin_unlock(&sema->lock);
    return acquired ? 0 : 1;
}

static inline void up(struct semaphore *sema)
{
    list l;
    context next;

    spin_lock(&sema->lock);
    sema->value++;
    l = list_get_next(&sema->waiters);
    if (l) {
        list_delete(l);
        next = struct_from_list(l, context, mutex_l);
    } else {
        next = 0;
    }
    spin_unlock(&sema->lock);
    if (!next)
        return;
    while (!frame_is_full(next->frame))
        kern_pause();
    context_schedule_return(next);
}

static inline void sema_init(struct semaphore *sema, int val)
{
    sema->value = val;
    list_init(&sema->waiters);
    spin_lock_init(&sema->lock);
}

#include "nv-kthread-q.h"
#include "nv-lock.h"

struct os_work_queue {
    nv_kthread_q_t nvk;
};

typedef struct nv_irq_count_info_s
{
    int    irq;
    NvU64  unhandled;
    NvU64  total;
    NvU64  last_unhandled;
} nv_irq_count_info_t;

struct nv_dma_device {
    struct {
        NvU64 start;
        NvU64 limit;
    } addressable_range;

    NvBool nvlink;
};

typedef struct nvidia_pte_s {
    NvU64           phys_addr;
    unsigned long   virt_addr;
    NvU64           dma_addr;
    unsigned int    page_count;
} nvidia_pte_t;

#define pfn_valid(pfn)  ((pfn) < (INVALID_PHYSICAL >> PAGELOG))

typedef struct nv_alloc_s {
    struct nv_alloc_s *next;
    struct device     *dev;
    atomic_t           usage_count;
    struct {
        NvBool contig      : 1;
        NvBool guest       : 1;
        NvBool zeroed      : 1;
        NvBool aliased     : 1;
        NvBool user        : 1;
        NvBool node        : 1;
        NvBool peer_io     : 1;
        NvBool physical    : 1;
        NvBool unencrypted : 1;
        NvBool coherent    : 1;
    } flags;
    unsigned int   cache_type;
    unsigned int   num_pages;
    unsigned int   order;
    unsigned int   size;
    nvidia_pte_t **page_table;          /* list of physical pages allocated */
    unsigned int   pid;
    NvU64         *user_pages;
    NvU64          guest_id;            /* id of guest VM */
    NvS32          node_id;             /* Node id for memory allocation when node is set in flags */
    void          *import_priv;
    sg_list        import_sgt;
} nv_alloc_t;

/* this is a general os-specific state structure. the first element *must* be
   the general state structure, for the generic unix-based code */
declare_closure_struct(0, 0, void, nvidia_isr);
declare_closure_struct(0, 0, void, nvidia_isr_kthread_bh);
declare_closure_struct(0, 0, void, nvidia_isr_msix);
declare_closure_struct(0, 0, void, nvidia_isr_msix_kthread_bh);
declare_closure_struct(0, 0, void, nvidia_isr_bh_unlocked);
typedef struct nv_nanos_state_s {
    nv_state_t nv_state;
    atomic_t usage_count;
    NvU32    suspend_count;
    struct device  *dev;
    struct pci_dev *pci_dev;

    /* IBM-NPU info associated with this GPU */
    nv_ibmnpu_info_t *npu;

    nvidia_stack_t *sp[NV_DEV_STACK_COUNT];
    char registry_keys[NV_MAX_REGISTRY_KEYS_LENGTH];

    /* get a timer callback every second */
    struct nv_timer rc_timer;

    /* lock for Nanos-specific data, not used by core rm */
    struct semaphore ldata_lock;

    NvU32 minor_num;
    struct nv_nanos_state_s *next;

    closure_struct(nvidia_isr, isr);
    closure_struct(nvidia_isr_kthread_bh, isr_bh);
    closure_struct(nvidia_isr_msix, isr_msix);
    closure_struct(nvidia_isr_msix_kthread_bh, isr_msix_bh);
    closure_struct(nvidia_isr_bh_unlocked, bottom_half_q_item);

    /* Lock for unlocked bottom half protecting common allocated stack */
    void *isr_bh_unlocked_mutex;

    NvBool tce_bypass_enabled;
    NvU32 num_intr;

    /* Lock serializing ISRs for different MSI-X vectors */
    struct spinlock msix_isr_lock;

    /* Lock serializing bottom halves for different MSI-X vectors */
    void *msix_bh_mutex;

    NvU64 numa_memblock_size;

    /* GPU user mapping revocation/remapping (only for non-CTL device) */
    struct semaphore mmap_lock; /* Protects all fields in this category */
    struct list open_files;
    NvBool all_mappings_revoked;
    NvBool safe_to_mmap;
    NvBool gpu_wakeup_callback_needed;

    struct nv_timer snapshot_timer;
    struct spinlock snapshot_timer_lock;
    void (*snapshot_callback)(void *context);

    /* count for unhandled, total and timestamp of irq */
    nv_irq_count_info_t *irq_count;

    /* Max number of irq triggered and are getting tracked */
    NvU16 current_num_irq_tracked;

    struct nv_dma_device dma_dev;
} nv_nanos_state_t;

extern NvBool nv_ats_supported;

extern NvU32 NVreg_RegisterPCIDriver;

extern NvU32 num_probed_nv_devices;
extern NvU32 num_nv_devices;

#define NV_MAY_SLEEP()  (!in_interrupt())

#define NV_EFI_ENABLED() 0

#if defined(NVCPU_X86_64) && !defined(NV_XEN_SUPPORT_FULLY_VIRTUALIZED_KERNEL)
#define NV_ENABLE_PAT_SUPPORT
#endif

#define NV_PAT_MODE_DISABLED    0
#define NV_PAT_MODE_KERNEL      1
#define NV_PAT_MODE_BUILTIN     2

extern int nv_pat_mode;

#define NV_READ_CR4()   ({                                      \
    unsigned long val;                                          \
    asm volatile("mov %%cr4, %0" : "=r" (val) : : "memory");    \
    val;                                                        \
})
#define NV_WRITE_CR4(cr4)   mov_to_cr("cr4", cr4)


#define NV_PCIE_CFG_MAX_OFFSET  0x1000

typedef enum
{
    NV_MEMORY_TYPE_SYSTEM,      /* Memory mapped for ROM, SBIOS and physical RAM. */
    NV_MEMORY_TYPE_REGISTERS,
    NV_MEMORY_TYPE_FRAMEBUFFER,
    NV_MEMORY_TYPE_DEVICE_MMIO, /* All kinds of MMIO referred by NVRM e.g. BARs and MCFG of device */
} nv_memory_type_t;

typedef struct nvidia_event
{
    struct nvidia_event *next;
    nv_event_t event;
} nvidia_event_t;

#define min MIN
#define max MAX

#define likely(x)   (x)
#define unlikely(x) (x)

#define memcpy(d, s, n)         ({ runtime_memcpy(d, s, n); d; })
#define memset(p, v, l)         ({ runtime_memset((void *)(p), v, l); (void *)(p); })
#define memcmp                  runtime_memcmp
#define strcmp                  runtime_strcmp
#define strlen                  runtime_strlen
#define strstr                  runtime_strstr
#define strchr                  runtime_strchr
#define strncpy(dest, src, len) ({  \
    runtime_memcpy(dest, src, MIN(runtime_strlen(src) + 1, len)); dest; \
})
#define snprintf                rsnprintf

#define printk  rprintf
#define pr_info rprintf
#define pr_err  rprintf

#define KERN_ERR
#define KERN_INFO
#define KERN_DEBUG

#define NV_GFP_KERNEL   0
#define NV_GFP_ATOMIC   0
#define NV_GFP_NO_OOM   0

#if defined(NVCPU_AARCH64) || defined(NVCPU_PPC64LE)
#define NV_ALLOW_WRITE_COMBINING(mt)    1
#elif defined(NVCPU_X86_64)
#if defined(NV_ENABLE_PAT_SUPPORT)
#define NV_ALLOW_WRITE_COMBINING(mt)    \
    ((nv_pat_mode != NV_PAT_MODE_DISABLED) && \
     ((mt) != NV_MEMORY_TYPE_REGISTERS))
#else
#define NV_ALLOW_WRITE_COMBINING(mt)    0
#endif
#endif

#define NV_MAX_RECURRING_WARNING_MESSAGES 10

#if defined(NV_DBG_MEM)
#define NV_DBG_MEMINFO NV_DBG_ERRORS
#else
#define NV_DBG_MEMINFO NV_DBG_INFO
#endif

#define NV_MEM_TRACKING_PAD_SIZE(size) \
    (size) = NV_ALIGN_UP((size + sizeof(void *)), sizeof(void *))

#define NV_MEM_TRACKING_HIDE_SIZE(ptr, size)            \
    if ((ptr != NULL) && (*(ptr) != NULL))              \
    {                                                   \
        NvU8 *__ptr;                                    \
        *(unsigned long *) *(ptr) = (size);             \
        __ptr = *(ptr); __ptr += sizeof(void *);        \
        *(ptr) = (void *) __ptr;                        \
    }

#define NV_MEM_TRACKING_RETRIEVE_SIZE(ptr, size)        \
    {                                                   \
        NvU8 *__ptr = (ptr); __ptr -= sizeof(void *);   \
        (ptr) = (void *) __ptr;                         \
        (size) = *(unsigned long *) (ptr);              \
    }

#define NV_PRINT_AT(nv_debug_level,at)                                           \
    {                                                                            \
        nv_printf(nv_debug_level,                                                \
            "NVRM: VM: %s:%d: %p, %d page(s), count = %d, flags = 0x%08x, "      \
            "page_table = %p\n",  __FUNCTION__, __LINE__, at,                    \
            at->num_pages, NV_ATOMIC_READ(at->usage_count),                      \
            at->flags, at->page_table);                                          \
    }

#define WARN_ON(x)      ({ boolean b = !!(x); b; })
#define BUG_ON(expr)    assert(!(expr))

#define BUILD_BUG_ON(expr)                  build_assert(!(expr))
#define BUILD_BUG_ON_NOT_POWER_OF_2(expr)   build_assert(((expr) & ((expr) - 1)) == 0)

#define ZERO_SIZE_PTR       pointer_from_u64(16)
#define ZERO_OR_NULL_PTR(p) (u64_from_pointer(p) <= u64_from_pointer(ZERO_SIZE_PTR))

#define NV_KMALLOC(ptr, size)   do {                                                        \
    ptr = ((size) != 0) ? allocate(heap_locked(get_kernel_heaps()), size) : ZERO_SIZE_PTR;  \
    if (ptr == INVALID_ADDRESS)                                                             \
        ptr = 0;                                                                            \
} while (0)

#define NV_KZALLOC(ptr, size)   do {    \
    NV_KMALLOC(ptr, size);              \
    if (ptr) zero(ptr, size);           \
} while (0)

#define NV_KMALLOC_ATOMIC   NV_KMALLOC
#define NV_KMALLOC_NO_OOM   NV_KMALLOC

#define NV_KFREE(ptr, size) do {                                            \
    if (!ZERO_OR_NULL_PTR(ptr))                                             \
        deallocate(heap_locked(get_kernel_heaps()), (void *) (ptr), size);  \
} while (0)

#define NV_UVM_GFP_FLAGS    0
#define vmalloc(size)       kmalloc(size, 0)
#define vzalloc(size)       kzalloc(size, 0)
#define ksize(p)            objcache_from_object(u64_from_pointer(p), PAGESIZE_2M)->pagesize
#define is_vmalloc_addr(p)  false
#define vfree               kfree

static inline void *kmalloc(unsigned long size, int flags)
{
    void *p;
    NV_KMALLOC(p, size);
    return p;
}

static inline void *kzalloc(unsigned long size, int flags)
{
    void *p;
    NV_KMALLOC(p, size);
    if (!ZERO_OR_NULL_PTR(p))
        zero(p, size);
    return p;
}

static inline void *krealloc(const void *p, unsigned long new_size, int flags)
{
    unsigned long size = ksize(p);
    void *new_p;
    NV_KMALLOC(new_p, new_size);
    if (!ZERO_OR_NULL_PTR(p) && !ZERO_OR_NULL_PTR(new_p))
        runtime_memcpy(new_p, p, MIN(size, new_size));
    NV_KFREE(p, size);
    return new_p;
}

static inline void kfree(const void *p)
{
    NV_KFREE(p, -1ull);
}

/*
 * If the host OS has page sizes larger than 4KB, we may have a security
 * problem. Registers are typically grouped in 4KB pages, but if there are
 * larger pages, then the smallest userspace mapping possible (e.g., a page)
 * may give more access than intended to the user.
 */
#define NV_4K_PAGE_ISOLATION_REQUIRED(addr, size)                       \
    ((PAGESIZE > NV_RM_PAGE_SIZE) &&                                    \
     ((size) <= NV_RM_PAGE_SIZE) &&                                     \
     (((addr) >> NV_RM_PAGE_SHIFT) ==                                   \
        (((addr) + (size) - 1) >> NV_RM_PAGE_SHIFT)))

static inline void *nv_ioremap(NvU64 phys, NvU64 size, pageflags flags)
{
    size = pad(size, PAGESIZE);
    heap vh = (heap)heap_virtual_page(get_kernel_heaps());
    void *ptr = allocate(vh, size);
    if (ptr != INVALID_ADDRESS) {
        map(u64_from_pointer(ptr), phys & ~PAGEMASK, size, flags);
        NV_MEMDBG_ADD(ptr, size);
        ptr += phys & PAGEMASK;
    } else {
        ptr = 0;
    }
    return ptr;
}

static inline void *nv_ioremap_nocache(NvU64 phys, NvU64 size)
{
    return nv_ioremap(phys, size, pageflags_writable(pageflags_device()));
}

static inline void *nv_ioremap_cache(NvU64 phys, NvU64 size)
{
    return nv_ioremap(phys, size, pageflags_writable(pageflags_memory()));
}

static inline void *nv_ioremap_wc(NvU64 phys, NvU64 size)
{
    return nv_ioremap_nocache(phys, size);
}

static inline void nv_iounmap(void *ptr, NvU64 size)
{
    u64 vaddr = u64_from_pointer(ptr) & ~PAGEMASK;
    size = pad(size, PAGESIZE);
    NV_MEMDBG_REMOVE(vaddr, size);
    unmap_pages(vaddr, size);
    heap vh = (heap)heap_virtual_page(get_kernel_heaps());
    deallocate_u64(vh, vaddr, size);
}

#define MODULE_NAME "nvidia"

static inline NvBool nv_platform_supports_numa(nv_nanos_state_t *nvl)
{
    return NV_FALSE;
}

static inline NvU64 nv_phys_to_dma(struct device *dev, NvU64 pa)
{
    return pa;
}

static inline NvBool nv_dma_maps_swiotlb(struct device *dev)
{
    return NV_FALSE;
}

static inline NvBool nv_numa_node_has_memory(int node_id)
{
    if (node_id < 0 || node_id >= 1)
        return NV_FALSE;
    return NV_TRUE;
}

#define NV_ALLOC_PAGES_NODE(ptr, nid, order)  do                \
    {                                                           \
        heap h = (heap)heap_linear_backed(get_kernel_heaps());  \
        ptr = allocate_u64(h, PAGESIZE << (order));             \
        if (ptr == INVALID_PHYSICAL)                            \
            ptr = 0;                                            \
    } while (0)

#define NV_GET_FREE_PAGES(ptr, order)   NV_ALLOC_PAGES_NODE(ptr, 0, order)

#define NV_FREE_PAGES(ptr, order)   do                          \
    {                                                           \
        heap h = (heap)heap_linear_backed(get_kernel_heaps());  \
        deallocate_u64(h, ptr, PAGESIZE << (order));            \
    } while (0)

static inline NvUPtr nv_vmap(nvidia_pte_t **pages, NvU32 page_count,
                             NvBool cached, NvBool unencrypted)
{
    NvU64 size = page_count * PAGESIZE;
    pageflags prot = pageflags_writable(cached ? pageflags_memory() : pageflags_device());
    heap vh = (heap)heap_virtual_page(get_kernel_heaps());
    void *ptr;

    ptr = allocate(vh, size);
    if (ptr != INVALID_ADDRESS) {
        for (NvU32 i = 0; i < page_count; i++)
            map(u64_from_pointer(ptr + i * PAGESIZE), pages[i]->phys_addr, PAGESIZE, prot);
        NV_MEMDBG_ADD(ptr, size);
    } else {
        ptr = 0;
    }
    return (NvUPtr)ptr;
}

static inline void nv_vunmap(NvUPtr vaddr, NvU32 page_count)
{
    NvU64 size = page_count * PAGESIZE;
    heap vh = (heap)heap_virtual_page(get_kernel_heaps());

    unmap_pages(vaddr, size);
    deallocate_u64(vh, vaddr, size);
    NV_MEMDBG_REMOVE((void *)vaddr, size);
}

#define NV_CLI()                    disable_interrupts()
#define NV_SAVE_FLAGS(eflags)       do { eflags = read_flags(); } while (0)
#define NV_RESTORE_FLAGS(eflags)    irq_restore(eflags)

#define NV_VMA_SIZE(vma)    range_span((vma)->node.r)

static inline sysreturn nv_io_remap_page_range(vmap vm, NvU64 phys_addr, NvU64 size,
                                               pageflags flags)
{
    u64 virt = vm->node.r.start;
    remap(virt, phys_addr, size, flags);
    return virt;
}

#define NV_GET_CURRENT_PROCESS()        ({ thread t = current; int pid = t ? t->p->pid : 0; pid; })
#define NV_COPY_TO_USER(to, from, n)    (copy_to_user(to, from, n) == false)
#define NV_COPY_FROM_USER(to, from, n)  (copy_from_user(from, to, n) == false)

#define NV_GET_PAGE_COUNT(page_ptr) 1

#define NV_MAYBE_RESERVE_PAGE(ptr_ptr)
#define NV_MAYBE_UNRESERVE_PAGE(page_ptr)

#define on_each_cpu(func, info, wait)

#if defined(NVCPU_X86_64)
#define CACHE_FLUSH()  asm volatile("wbinvd":::"memory")
#define WRITE_COMBINE_FLUSH() asm volatile("sfence":::"memory")
#elif defined(NVCPU_AARCH64)
    static inline void nv_flush_cache_cpu(void *info)
    {
        if (!nvos_is_chipset_io_coherent())
        {
            WARN_ONCE(0, "NVRM: kernel does not support flush_cache_all()\n");
        }
    }
#define CACHE_FLUSH()            nv_flush_cache_cpu(NULL)
#define CACHE_FLUSH_ALL()        on_each_cpu(nv_flush_cache_cpu, NULL, 1)
#define WRITE_COMBINE_FLUSH()    mb()
#elif defined(NVCPU_PPC64LE)
#define CACHE_FLUSH()            asm volatile("sync;  \n" \
                                              "isync; \n" ::: "memory")
#define WRITE_COMBINE_FLUSH()    CACHE_FLUSH()
#endif

static inline int nv_kmem_cache_alloc_stack(nvidia_stack_t **stack)
{
    nvidia_stack_t *sp = NULL;
#if defined(NVCPU_X86_64)
    NV_KMALLOC(sp, sizeof(*sp));
    if (sp == NULL)
        return -1;
    sp->size = sizeof(sp->stack);
    sp->top = sp->stack + sp->size;
#endif
    *stack = sp;
    return 0;
}

static inline void nv_kmem_cache_free_stack(nvidia_stack_t *stack)
{
#if defined(NVCPU_X86_64)
    if (stack != NULL)
    {
        NV_KFREE(stack, sizeof(*stack));
    }
#endif
}

#if defined(NVCPU_X86_64)
/*
 * RAM is cached on Linux by default, we can assume there's
 * nothing to be done here. This is not the case for the
 * other memory spaces: we will have made an attempt to add
 * a WC MTRR for the frame buffer.
 *
 * If a WC MTRR is present, we can't satisfy the WB mapping
 * attempt here, since the achievable effective memory
 * types in that case are WC and UC, if not it's typically
 * UC (MTRRdefType is UC); we could only satisfy WB mapping
 * requests with a WB MTRR.
 */
#define NV_ALLOW_CACHING(mt)            ((mt) == NV_MEMORY_TYPE_SYSTEM)
#else
#define NV_ALLOW_CACHING(mt)            ((mt) != NV_MEMORY_TYPE_REGISTERS)
#endif

extern nv_nanos_state_t *nv_linux_devices;

extern struct semaphore nv_linux_devices_lock;
#define LOCK_NV_LINUX_DEVICES()     down(&nv_linux_devices_lock)
#define UNLOCK_NV_LINUX_DEVICES()   up(&nv_linux_devices_lock)

typedef enum
{
    NV_FOPS_STACK_INDEX_MMAP,
    NV_FOPS_STACK_INDEX_IOCTL,
    NV_FOPS_STACK_INDEX_COUNT
} nvidia_entry_point_index_t;

typedef struct nvfd {
    file f;
    closure_struct(fdesc_ioctl, ioctl);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_mmap, mmap);
    closure_struct(fdesc_close, close);
    nv_file_private_t nvfp;
    nvidia_stack_t *sp;
    nvidia_stack_t *fops_sp[NV_FOPS_STACK_INDEX_COUNT];
    struct semaphore fops_sp_lock[NV_FOPS_STACK_INDEX_COUNT];
    nv_alloc_t *free_list;
    void *nvptr;
    nvidia_event_t *event_data_head, *event_data_tail;
    NvBool dataless_event_pending;
    nv_spinlock_t fp_lock;
    blockq waitqueue;
    NvU32 *attached_gpus;
    size_t num_attached_gpus;
    nv_alloc_mapping_context_t mmap_context;
    u64 rdev;
    struct list entry;
} *nvfd;

static inline nvfd nv_get_nvlfp_from_nvfp(nv_file_private_t *nvfp)
{
    return struct_from_field(nvfp, nvfd, nvfp);
}

static inline nvidia_stack_t *nv_nvlfp_get_sp(nvfd nvlfp, nvidia_entry_point_index_t which)
{
#if defined(NVCPU_X86_64)
    if (rm_is_altstack_in_use())
    {
        down(&nvlfp->fops_sp_lock[which]);
        return nvlfp->fops_sp[which];
    }
#endif
    return NULL;
}

static inline void nv_nvlfp_put_sp(nvfd nvlfp, nvidia_entry_point_index_t which)
{
#if defined(NVCPU_X86_64)
    if (rm_is_altstack_in_use())
    {
        up(&nvlfp->fops_sp_lock[which]);
    }
#endif
}

#include "nv-proto.h"

#define NV_GET_NANOS_FILE_PRIVATE(f) struct_from_field(f->close, nvfd, close)

#define NV_GET_NVL_FROM_FILEP(filep)    (((nvfd)filep)->nvptr)
#define NV_GET_NVL_FROM_NV_STATE(nv)    ((nv_nanos_state_t *)nv->os_state)

#define NV_STATE_PTR(nvl)   &(((nv_nanos_state_t *)(nvl))->nv_state)

#define NV_ATOMIC_READ(data)            (data)
#define NV_ATOMIC_SET(data,val)         ((data) = (val))
#define NV_ATOMIC_INC(data)             fetch_and_add_32(&(data), 1)
#define NV_ATOMIC_DEC(data)             fetch_and_add_32(&(data), -1)
#define NV_ATOMIC_DEC_AND_TEST(data)    (fetch_and_add_32(&(data), -1) == 1)

#define ATOMIC_INIT(i)  (i)

#define atomic_read(ptr)            (*(ptr))
#define atomic_long_read(ptr)       (*(ptr))
#define atomic64_read(ptr)          (*(ptr))
#define atomic_set(ptr, val)        do {*(ptr) = (val);} while (0)
#define atomic_long_set(ptr, val)   do {*(ptr) = (val);} while (0)
#define atomic64_set(ptr, val)      do {*(ptr) = (val);} while (0)
#define atomic_long_add(n, ptr)     __sync_fetch_and_add(ptr, n)
#define atomic64_add(n, ptr)        __sync_fetch_and_add(ptr, n)
#define atomic64_sub(n, ptr)        __sync_fetch_and_add(ptr, -(n))
#define atomic_long_sub(n, ptr)     __sync_fetch_and_add(ptr, -(n))
#define atomic_inc(ptr)             __sync_fetch_and_add(ptr, 1)
#define atomic_long_inc(ptr)        __sync_fetch_and_add(ptr, 1)
#define atomic64_inc(ptr)           __sync_fetch_and_add(ptr, 1)
#define atomic_long_dec(ptr)        __sync_fetch_and_add(ptr, -1)
#define atomic_inc_return(ptr)      (__sync_fetch_and_add(ptr, 1) + 1)
#define atomic64_inc_return(ptr)    (__sync_fetch_and_add(ptr, 1) + 1)
#define atomic_dec_return(ptr)      (__sync_fetch_and_add(ptr, -1) - 1)
#define atomic64_dec_return(ptr)    (__sync_fetch_and_add(ptr, -1) - 1)
#define atomic_dec_and_test(ptr)    (__sync_fetch_and_add(ptr, -1) == 1)
#define atomic64_dec_and_test(ptr)  (__sync_fetch_and_add(ptr, -1) == 1)
#define atomic64_cmpxchg            __sync_val_compare_and_swap

#define atomic_inc_not_zero(ptr)    ({                                      \
    boolean res = true;                                                     \
    typeof(*ptr) v = *ptr;                                                  \
    while (1) {                                                             \
        if (!v) {res = false; break;}                                       \
        typeof(*ptr) new_v = __sync_val_compare_and_swap(ptr, v, v + 1);    \
        if (new_v == v) break;                                              \
        v = new_v;                                                          \
    }                                                                       \
    res;                                                                    \
})

#define atomic_dec_if_positive(ptr)    ({                                   \
    typeof(*ptr) v = *ptr;                                                  \
    while (1) {                                                             \
        if (!v) break;                                                      \
        typeof(*ptr) new_v = __sync_val_compare_and_swap(ptr, v, v - 1);    \
        if (new_v == v) break;                                              \
        v = new_v;                                                          \
    }                                                                       \
    v - 1;                                                                  \
})

static inline long atomic_long_read_acquire(atomic_long_t *p)
{
    long val = atomic_long_read(p);
    memory_barrier();
    return val;
}

static inline void atomic_long_set_release(atomic_long_t *p, long v)
{
    memory_barrier();
    atomic_long_set(p, v);
}

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define UVM_WRITE_ONCE(x, val) (ACCESS_ONCE(x) = (val))
#define UVM_READ_ONCE(x) ACCESS_ONCE(x)

#if NVCPU_IS_X86 || NVCPU_IS_X86_64
#define smp_mb__before_atomic() compiler_barrier()
#else
#define smp_mb__before_atomic() smp_mb()
#endif

#if NVCPU_IS_X86 || NVCPU_IS_X86_64
#define smp_mb__after_atomic() memory_barrier()
#else
#define smp_mb__after_atomic() smp_mb()
#endif

#define smp_load_acquire(p)                     \
    ({                                          \
        typeof(*(p)) __v = UVM_READ_ONCE(*(p)); \
        memory_barrier();                       \
        __v;                                    \
    })

#define smp_store_release(p, v)     \
    do {                            \
        memory_barrier();           \
        UVM_WRITE_ONCE(*(p), v);    \
    } while (0)

#define atomic_read_acquire(p) smp_load_acquire(p)

#define atomic_set_release(p, v) smp_store_release(p, v)

#define MODULE_INSTANCE_NUMBER 0

#define EXPORT_SYMBOL(s)

#define LIST_HEAD(var)              struct list var = {.prev = &var, .next = &var}
#define INIT_LIST_HEAD              list_init
#define list_add(node, list)        list_insert_after(list, node)
#define list_add_tail(node, list)   list_push_back(list, node)
#define list_move_tail(node, list)  list_push_back(list, node)
#define list_del                    list_delete
#define list_del_init               list_delete
#define list_is_singular            list_singular

#define list_entry(l, type, member)     struct_from_list(l, type *, member)
#define list_first_entry(l, type, f)    struct_from_list(list_begin(l), type *, f)

#define list_for_each_entry(e, l, f)                                    \
    for (e = struct_from_list((l)->next, typeof(e), f); &(e)->f != (l); \
        e = struct_from_list((e)->f.next, typeof(e), f))

#define list_for_each_entry_safe(e, n, l, f)                                            \
    for (e = struct_from_list(list_begin(l), typeof(e), f);                             \
        n = struct_from_list((e)->f.next, typeof(n), f), &(e)->f != list_end(l); e = n)

static inline NvU64 nv_compress_nvlink_addr(NvU64 addr)
{
    return addr;
}

static inline NvU64 nv_expand_nvlink_addr(NvU64 addr47)
{
    return addr47;
}

static inline int nv_get_numa_status(nv_nanos_state_t *nvl)
{
    return NV_IOCTL_NUMA_STATUS_DISABLED;
}

static inline int nv_set_numa_status(nv_nanos_state_t *nvl, int status)
{
    return -EINVAL;
}

static inline boolean test_bit(u64 bit, const unsigned long *addr)
{
    const unsigned long *p = addr + (bit >> 6);

    return ((*p) >> (bit & 0x3f)) & 0x1;
}

static inline void __set_bit(u64 bit, unsigned long *addr)
{
    u64 mask = U64_FROM_BIT(bit & 0x3f);
    unsigned long *p = addr + (bit >> 6);

    *p |= mask;
}

static inline void __clear_bit(u64 bit, unsigned long *addr)
{
    u64 mask = U64_FROM_BIT(bit & 0x3f);
    unsigned long *p = addr + (bit >> 6);

    *p &= ~mask;
}

static inline boolean __test_and_set_bit(u64 bit, unsigned long *addr)
{
    u64 mask = U64_FROM_BIT(bit & 0x3f);
    unsigned long *p = addr + (bit >> 6);
    unsigned long old = *p;

    *p |= mask;
    return (old & mask) != 0;
}

#endif
