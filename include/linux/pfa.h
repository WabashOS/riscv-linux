#ifndef _PFA_H
#define _PFA_H

#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mutex.h>
#include <linux/pfa_stat.h>

#ifdef CONFIG_PFA_DEBUG
/* Linux BUG_ON acts really weird (sometimes crashes in strange ways), plus it
 * doesn't print out as much info as I'd like */
#define PFA_ASSERT(COND, MSG, ...) \
  do {  \
    if(unlikely(!(COND))) { \
      panic("PFA_ASSERT %s:%d: " MSG, __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
  } while(0)

#else
#define PFA_ASSERT(COND, MSG, ...) 
#endif

#ifdef CONFIG_PFA_VERBOSE
/* Use this for noisy messages you might want to turn off */
#define pfa_trace(M, ...) printk("PFA_TRACE: " M, ##__VA_ARGS__)
#else
#define pfa_trace(M, ...)
#endif

#define pfa_warn(M, ...) printk("PFA_WARNING: " M, ##__VA_ARGS__)
// #define pfa_warn(M, ...) 

#ifdef CONFIG_PFA

/* The PFA can only work for one task at a time right now. 
 * NULL if no one has registered with the PFA. */
#define PFA_TASK_BITS 5
#define PFA_MAX_TASKS (1 << PFA_TASK_BITS)
extern struct task_struct *pfa_tsk[PFA_MAX_TASKS];

/* Remote PTE */
#define PFA_PGID_SHIFT  12
#define PFA_PROT_SHIFT  2

/* pgid is the metadata we store in a PTE before making it remote. It contains
 * the swap offset (we assume swp_type=0) and the pfa_tsk_id of the owner
 * | 0000 | tsk_id (5 bits) | offset (23 bits) | */
#define PFA_PGID_OFFSET_BITS 23
#define PFA_PGID_TSK_BITS 5
typedef uint32_t pfa_pgid_t;

/* Maximum size of a PageID (in bits). Defined in pfa_spec. */
#define PFA_PGID_BITS 28 
/* Location of PGID in an eviction value (defined in pfa_spec) */
#define PFA_EVICT_PGID_SHIFT 36


/* Global PFA lock
 * Protects access to PFA (callers of sensitive PFA functions need to acquire
 * this before calling).
 * NOTE: Often held with mm->mmap_sem. To avoid deadlock, If you need mmap_sem,
 * always down it before locking pfa_mutex. */
extern struct mutex pfa_mutex_global;
/* Only protects the evictq (and subsequent polling for completion) */
extern struct mutex pfa_mutex_evict;

/* Macros here mostly to make it easier to track locking behavior */
// #define pfa_trace_locks(M, ...) printk("PFA_TRACE_LOCKS: " M, ##__VA_ARGS__)
#define pfa_trace_locks(M, ...) 

#define pfa_lock(LOCK) do { \
  pfa_trace_locks("Locking PFA: %s:%d\n", __FILE__, __LINE__); \
  mutex_lock(&pfa_mutex_##LOCK); \
  pfa_trace_locks("Got it!\n"); \
} while(0)

static inline int __pfa_trylock(const char *file, int line, struct mutex *lock) {
  int res = mutex_trylock(lock);
  if(res)
    pfa_trace_locks("Locking PFA: %s:%d\n", file, line);
  else
    pfa_trace_locks("Failed to Lock PFA: %s:%d\n", file, line);

  return res;
}
#define pfa_trylock(LOCK) __pfa_trylock(__FILE__, __LINE__, &pfa_mutex_##LOCK)

#define pfa_unlock(LOCK) do { \
  mutex_unlock(&pfa_mutex_##LOCK); \
  pfa_trace_locks("Unlocked PFA: %s:%d\n", __FILE__, __LINE__); \
} while(0)

/* Don't use BUG_ON(!mutex_is_locked...), it breaks in bizzare ways */
#define pfa_assert_lock(LOCK) \
  do { \
    if(!mutex_is_locked(&pfa_mutex_##LOCK)) \
      panic("pfa_assert_lock"); \
  } while(0)

/* initialize the system, only call once! */
void pfa_init(void);

/* We rate-limit our evictions since the PFA doesn't right now 
 * Call this right before sending traffic to the memory blade. */
void pfa_limit_evict(void);

/* Evict a page to the pfa. */
void pfa_evict(swp_entry_t swp_ent, uintptr_t page_paddr, uintptr_t vaddr,
    struct task_struct *tsk);

int64_t pfa_nnew(void);

/* Fetch and report every newpage from PFA.
 * mmap_sem_tsk: Caller may optionally hold exactly one mmap_sem. If it does
 *   hold one, pass that task pfa_tsk_id here, otherwise pass -1.
 * Caller must hold pfa_lock */
void pfa_drain_newq(int mmap_sem_tsk);

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
static inline pfa_pgid_t pfa_swp_to_pgid(swp_entry_t ent, int tsk_id)
{
  pfa_pgid_t pgid = 0;
  pgoff_t off;
  /* This is pretty hacky. We assume 2 things:
   * 1. Linux always uses the first swp device when evicting to PFA (probably
   *    safe so long as it never fills up from non-PFA swap activity)
   * 2. Linux swap offset only uses page_id bits (52). Probably safe since the
   *    offset seems to be a monotonically increasing set of blockIDs (would need
   *    to swap out PBs of data to overflow
   */
  PFA_ASSERT(swp_type(ent) == 0, "Swapping to swp device other than 0 (%d)",
      swp_type(ent));
  off = swp_offset(ent);
  PFA_ASSERT(off < (1ul << PFA_PGID_OFFSET_BITS), "Swap page offset too large (wouldn't fit in pgid)\n");
  PFA_ASSERT(tsk_id >= 0 && tsk_id < PFA_MAX_TASKS, "Invalid task id: %d\n", tsk_id);

  pgid = tsk_id << PFA_PGID_OFFSET_BITS;
  pgid |= off; 
  return pgid;
}

/* Create a swp_entry_t from a pgid */
static inline swp_entry_t pfa_pgid_to_swp(pfa_pgid_t pgid)
{
  int off = pgid & ~(~0u << PFA_PGID_OFFSET_BITS);
  return swp_entry(0, off);
}

static inline int pfa_pgid_to_tsk(pfa_pgid_t pgid)
{
  return pgid >> PFA_PGID_OFFSET_BITS;
}

/* Create a remote pte */
static inline pte_t pfa_mk_remote_pte(swp_entry_t swp_ent, pgprot_t prot,
    int tsk_id)
{
  pfa_pgid_t pgid = pfa_swp_to_pgid(swp_ent, tsk_id);
  /* The page will be marked "fetched" after the PFA fetches it 
   * this flag gets cleared after bookkeeping */
  prot = __pgprot(pgprot_val(prot) | _PAGE_FETCHED );

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

/* Assigns "tsk" to the PFA and gives it a pfa_tsk_id.
 * Returns 1 on success, 0 on failure (likely due to too many active pfa
 * tasks) */
int pfa_set_tsk(struct task_struct *tsk);

/* Must down pfa_tsk->mm->mmap_sem before calling.
 * tsk_id: The struct task_struct->pfa_tsk_id feild*/
void pfa_clear_tsk(int tsk_id);

#define is_pfa_tsk(tsk) (tsk->pfa_tsk_id != -1)
static inline struct task_struct *pfa_get_tsk(int tsk_id)
{
  PFA_ASSERT((tsk_id < PFA_MAX_TASKS && tsk_id >= 0), "Invalid task ID: %d", tsk_id);
  return pfa_tsk[tsk_id];
}

#else //ifdef CONFIG_PFA

/* initialize the system, only call once! */
void pfa_init(void);

/* The PFA can only work for one task at a time right now. 
 * NULL if no one has registered with the PFA. */
#define PFA_TASK_BITS 5
#define PFA_MAX_TASKS (1 << PFA_TASK_BITS)
extern struct task_struct *pfa_tsk[PFA_MAX_TASKS];

/* Assigns "tsk" to the PFA and gives it a pfa_tsk_id.
 * Returns 1 on success, 0 on failure (likely due to too many active pfa
 * tasks) */
int pfa_set_tsk(struct task_struct *tsk);

/* Must down pfa_tsk->mm->mmap_sem before calling.
 * tsk_id: The struct task_struct->pfa_tsk_id feild*/
void pfa_clear_tsk(int tsk_id);

#define is_pfa_tsk(tsk) (tsk->pfa_tsk_id != -1)
static inline struct task_struct *pfa_get_tsk(int tsk_id)
{
  PFA_ASSERT((tsk_id < PFA_MAX_TASKS && tsk_id >= 0), "Invalid task ID: %d", tsk_id);
  return pfa_tsk[tsk_id];
}

#endif //ifdef CONFIG_PFA

#endif //ifdef __PFA_H__
