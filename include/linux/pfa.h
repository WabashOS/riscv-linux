#ifndef _PFA_HELPER_H
#define _PFA_HELPER_H

#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mutex.h>

/* The PFA can only work for one task at a time right now. 
 * NULL if no one has registered with the PFA. */
extern struct task_struct *pfa_tsk;

/* If set, linux uses PFA. Otherwise, rswap is used */
#define USE_PFA

/* Only turn this on for extra paranoid debugging (significant performance hit) */
#define PFA_DEBUG

/* Remote PTE */
#define PFA_PGID_SHIFT  12
#define PFA_PROT_SHIFT  2

/* Use this for noisy messages you might want to turn off */
// #define pfa_trace(M, ...) printk("PFA_TRACE: " M, ##__VA_ARGS__)
#define pfa_trace(M, ...) 

/* pgid is a compressed form of swp_entry_t. It assumes that type=0 and then
 * just uses the offset as pgid */
typedef uint32_t pfa_pgid_t;

/* Maximum size of a PageID (in bits). Defined in pfa_spec. */
#define PFA_PGID_BITS 28 
/* Location of PGID in an eviction value (defined in pfa_spec) */
#define PFA_EVICT_PGID_SHIFT 36

/* Protects access to PFA (callers of sensitive PFA functions need to acquire
 * this before calling).
 * NOTE: Often held with mm->mmap_sem. To avoid deadlock, If you need mmap_sem,
 * always down it before locking pfa_mutex. */
extern struct mutex pfa_mutex;

/* Macros here mostly to make it easier to track locking behavior */
// #define pfa_trace_locks(M, ...) printk("PFA_TRACE_LOCKS: " M, ##__VA_ARGS__)
#define pfa_trace_locks(M, ...) 

#define pfa_lock() do { \
  pfa_trace_locks("Locking PFA: %s:%d\n", __FILE__, __LINE__); \
  mutex_lock(&pfa_mutex); \
  pfa_trace_locks("Got it!\n"); \
} while(0)

static inline int __pfa_trylock(const char *file, int line) {
  int res = mutex_trylock(&pfa_mutex);
  if(res)
    pfa_trace_locks("Locking PFA: %s:%d\n", file, line);
  else
    pfa_trace_locks("Failed to Lock PFA: %s:%d\n", file, line);

  return res;
}
#define pfa_trylock() __pfa_trylock(__FILE__, __LINE__)

#define pfa_unlock() do { \
  mutex_unlock(&pfa_mutex); \
  pfa_trace_locks("Unlocked PFA: %s:%d\n", __FILE__, __LINE__); \
} while(0)

#define pfa_assert_lock() BUG_ON(!mutex_is_locked(&pfa_mutex))

static inline uint64_t get_cycle(void)
{
  register unsigned long __v;
  __asm__ __volatile__ ("rdcycle %0" : "=r" (__v));
  return __v;
}

/* initialize the system, only call once! */
void pfa_init(void);

/* Evict a page to the pfa. */
void pfa_evict(swp_entry_t swp_ent, uintptr_t page_paddr, uintptr_t vaddr);

int64_t pfa_nnew(void);

/* Fetch and report every newpage from PFA.
 * Caller must down pfa_tsk->mm->mmap_sem
 * Caller must hold pfa_lock */
void pfa_drain_newq(void);

/* Provides enough free frames to the PFA to fill it's queues
 * Caller must hold pfa_lock */
void pfa_fill_freeq(void);

/* Handle a page fault due to PFA error (remote bit set in PTE)
 * Caller must down pfa_tsk->mm->mmap_sem */
int pfa_handle_fault(struct vm_fault *vmf);

/* Translate any virtual address to it's physical address 
 * note the kernel virt_to_phys only works for kernel addresses
 * pte: PTE of vaddr to translate
 * vaddr: virtual address to translate
 */
static inline uintptr_t pfa_vaddr_to_paddr(pte_t pte, uintptr_t vaddr)
{
  return (pte_pfn(pte) << PAGE_SHIFT) +
         (vaddr & ~(~0ul << PAGE_SHIFT));
}

/* Convert a swp entry to a pfa pageID */
static inline pfa_pgid_t pfa_swp_to_pgid(swp_entry_t ent)
{
  pgoff_t off;
  /* This is pretty hacky. We assume 2 things:
   * 1. Linux always uses the first swp device when evicting to PFA (probably
   *    safe so long as it never fills up from non-PFA swap activity)
   * 2. Linux swap offset only uses page_id bits (52). Probably safe since the
   *    offset seems to be a monotonically increasing set of blockIDs (would need
   *    to swap out PBs of data to overflow
   */
  BUG_ON(swp_type(ent) != 0);
  off = swp_offset(ent);
  BUG_ON(off >= (1ul << PFA_PGID_BITS));
  return off;
}

/* Create a swp_entry_t from a pgid */
static inline swp_entry_t pfa_pgid_to_swp(pfa_pgid_t pgid)
{
  return swp_entry(0, pgid);
}

/* Create a remote pte */
static inline pte_t pfa_mk_remote_pte(swp_entry_t swp_ent, pgprot_t prot)
{
  pfa_pgid_t pgid = pfa_swp_to_pgid(swp_ent);
  /* The page will be marked "fetched" after the PFA fetches it 
   * this flag gets cleared after bookkeeping */
  prot = __pgprot(pgprot_val(prot) | _PAGE_FETCHED);
  // BUG_ON(!pte_fetched(__pte(pgprot_val(prot))));
  return __pte(
        (pgid << PFA_PGID_SHIFT) |
        (pgprot_val(prot) << PFA_PROT_SHIFT) |
        _PAGE_REMOTE
       );
}

/* Retrieve the swp_entry_t from a remote pte */
static inline swp_entry_t pfa_remote_to_swp(pte_t ptep)
{
  return pfa_pgid_to_swp((pfa_pgid_t)(pte_val(ptep) >> PFA_PGID_SHIFT));
}

/* The frameq should hold frames in the PFA in FIFO order. 
 * It uses the page->lru list element which should be unused */
void pfa_frameq_push(struct page *frame);
struct page* pfa_frameq_pop(void);

/* Searches the frameq for paddr. Returns 1 if found, 0 otherwise.
 * This isn't super thread-safe, but it won't corrupt anything (it might cause
 * a crash under certain races) */
int pfa_frameq_search(uintptr_t paddr);

void pfa_set_tsk(struct task_struct *tsk);

/* Must down pfa_tsk->mm->mmap_sem before calling */
void pfa_clear_tsk(void);

static inline struct task_struct *pfa_get_tsk(void) { return pfa_tsk; }

#endif
