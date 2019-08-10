#ifndef _PFA_H
#define _PFA_H

#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mutex.h>
#include <linux/pfa_stat.h>
#include <linux/hashtable.h>

/* A generic in-place queue (no pointers) */
#define DEFINE_PQ(NAME, SIZE, TYPE) typedef struct { \
  int head; \
  int tail; \
  int cnt; \
  int size; \
  TYPE q[SIZE]; \
} NAME##_t

#define DECLARE_PQ(NAME, SIZE) NAME##_t NAME = {0, 0, 0, SIZE, {0} }

#define PQ_PUSH(Q, VAL) do { \
  PFA_ASSERT(Q.cnt != Q.size, "Pushing to full queue");  \
  Q.q[Q.head] = VAL;         \
  Q.head = (Q.head + 1) % Q.size; \
  Q.cnt++; \
} while(0)

/* Note: you can't use this like a normal function (it doesn't return anything)
 * you need to provide the destination to store into (literal symbol, not a pointer) */
#define PQ_POP(Q, DST) do { \
  PFA_ASSERT(Q.cnt != 0, "Popping from empty queue"); \
  DST = Q.q[Q.tail]; \
  Q.tail = (Q.tail + 1) % Q.size; \
  Q.cnt--; \
} while (0)

#define PQ_CNT(Q) Q.cnt

#ifdef CONFIG_PFA_DEBUG

#define PFA_DEOPTIMIZE_VAR(PTR) __asm__ __volatile__("" :: "m" (PTR))

/* Linux BUG_ON acts really weird (sometimes crashes in strange ways), plus it
 * doesn't print out as much info as I'd like */
#define PFA_ASSERT(COND, MSG, ...) \
  do {  \
    if(unlikely(!(COND))) { \
      pfa_dump_trace(); \
      panic("PFA_ASSERT (%d) %s:%d: " MSG, task_tgid_vnr(current), __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
  } while(0)

typedef struct dbg_page {
  void *pg;
  uintptr_t vaddr;
  void *priv;
  struct hlist_node _hash;
} dbg_page_t;

/* Add a page to the dbg_page structure.
 * pg - the page you would like to store, a copy will be made
 * vaddr - virtual address to use as a key
 * priv - optional private data to store along with page.
 */
void pfa_dbg_record_page(void *pg, uintptr_t vaddr, void *priv);

/* Read of a page (non-destructive).
 * Returns: dbg_page_t representing the page (if found) or NULL if not found
 */
dbg_page_t *pfa_dbg_get_page(uintptr_t vaddr);

/* Remove a page from the dbg_page structure and free it */ 
void pfa_dbg_clear_page(dbg_page_t *ref);

#else //CONFIG_PFA_DEBUG
#define PFA_ASSERT(COND, MSG, ...) 
#define PFA_DEOPTIMIZE_VAR(PTR)
#endif //CONFIG_PFA_DEBUG

#ifdef CONFIG_PFA_VERBOSE
// #define PFA_LOG_DEFER 1

#ifdef PFA_LOG_DEFER
#define PFA_LOG_SZ (4*1024*1024)
extern uint8_t *pfa_log;
extern size_t pfa_log_end;
extern spinlock_t pfa_log_mut;

/* Use this for noisy messages you might want to turn off */
#define pfa_trace(M, ...) do { \
  unsigned long flags; \
  spin_lock_irqsave(&pfa_log_mut, flags); \
  pfa_log_end += snprintf(pfa_log + pfa_log_end, PFA_LOG_SZ - pfa_log_end, "PFA_TRACE (%d): " M, task_tgid_vnr(current), ##__VA_ARGS__); \
  if(pfa_log_end > PFA_LOG_SZ) { \
    printk("pfa_trace buffer overflow!\n"); \
    pfa_log_end = 0; \
  } \
  spin_unlock_irqrestore(&pfa_log_mut, flags); \
} while(0)

/* This is a backup that is really slow. I don't know how to print the whole
 * string at once (it's MBs in size and printk won't do it in one shot).
 * You should probably use the dump_log command in gdb (it's much faster)
 */
static inline void pfa_dump_trace(void) {
  int i;
  for(i = 0; pfa_log[i] != 0 && i < pfa_log_end; i++) {
    printk(KERN_CONT "%c", pfa_log[i]);
  }

  memset(pfa_log, 0, pfa_log_end);
  pfa_log_end = 0;
}

#else //PFA_LOG_DEFER
#define pfa_trace(M, ...) printk("PFA_TRACE: " M, ##__VA_ARGS__)
#define pfa_dump_trace() 
#endif //PFA_LOG_DEFER

#else
#define pfa_trace(M, ...)
#define pfa_dump_trace() 
#endif //CONFIG_PFA_VERBOSE

#define pfa_warn(M, ...) printk(KERN_WARNING "PFA_WARNING: " M, ##__VA_ARGS__)
// #define pfa_warn(M, ...) 

#define vma_to_task(VMA) (VMA->vm_mm->owner)

// #if defined(CONFIG_PFA) || defined(CONFIG_PFA_SW_RMEM)

/* The PFA can only work for one task at a time right now. 
 * NULL if no one has registered with the PFA. */
#define PFA_MAX_TASKS 64 
extern struct task_struct *pfa_tsk[PFA_MAX_TASKS];

/* Remote PTE */
#define PFA_PGID_SHIFT  12
#define PFA_PROT_SHIFT  2

/* pgid is the metadata we store in a PTE before making it remote.*/
typedef uint64_t pfa_pgid_t;

/* Location of PGID in an eviction value (defined in pfa_spec) */
#define PFA_EVICT_RPN_SHIFT 36

/* size of remote page number part of pgid */
#define PFA_PGID_RPN_BITS  28 
/* size of SW reserved part of pgid (stores the tskID here)*/
#define PFA_PGID_SW_BITS   24 

/* Return the remote page number and sw reserved parts of a pageID
 * (respectively) */
#define pfa_pgid_rpn(PGID) (PGID & ((1 << PFA_PGID_RPN_BITS) - 1))
#define pfa_pgid_sw(PGID) (PGID >> PFA_PGID_RPN_BITS)

/* Remote page numbers will start from this value and go up */
#define PFA_RPN_BASE 4

/* Convert a swp entry to a pfa pageID */
static inline pfa_pgid_t pfa_swp_to_rpn(swp_entry_t ent)
{
  pfa_pgid_t rpn = 0;
  /* This is pretty hacky. We assume 2 things:
   * 1. Linux always uses the first swp device when evicting to PFA (probably
   *    safe so long as it never fills up from non-PFA swap activity)
   * 2. Linux swap offset only uses page_id bits (52). Probably safe since the
   *    offset seems to be a monotonically increasing set of blockIDs (would need
   *    to swap out PBs of data to overflow
   */
  PFA_ASSERT(swp_type(ent) == 0, "Swapping to swp device other than 0 (%d)",
      swp_type(ent));
  rpn = swp_offset(ent) + PFA_RPN_BASE;
  PFA_ASSERT(rpn < (1ul << PFA_PGID_RPN_BITS), "Swap page offset too large (wouldn't fit in pgid)\n");

  return rpn;
}

static inline pfa_pgid_t pfa_swp_to_pgid(swp_entry_t ent, int tsk_id)
{
  pfa_pgid_t pgid = pfa_swp_to_rpn(ent);
  
  PFA_ASSERT(tsk_id >= 0 && tsk_id < PFA_MAX_TASKS, "Invalid task id: %d\n", tsk_id);
  pgid |= (pfa_pgid_t)(tsk_id << PFA_PGID_RPN_BITS);
  return pgid;
}

/* Create a swp_entry_t from a pgid */
static inline swp_entry_t pfa_pgid_to_swp(pfa_pgid_t pgid)
{
  int off = pfa_pgid_rpn(pgid) - PFA_RPN_BASE;
  return swp_entry(0, off);
}

static inline int pfa_pgid_to_tsk(pfa_pgid_t pgid)
{
  return pfa_pgid_sw(pgid);
}

/* Global PFA lock
 * Protects access to PFA (callers of sensitive PFA functions need to acquire
 * this before calling).
 * NOTE: Often held with mm->mmap_sem. To avoid deadlock, If you need mmap_sem,
 * always down it before locking pfa_mutex. */
extern struct rw_semaphore pfa_mutex_global;

extern spinlock_t pfa_hw_mut;

#ifdef CONFIG_PFA_EM
/* This mutex enforces atomic reads/writes from/to the emulated PFA queues. */
extern spinlock_t pfa_em_mut;
#endif

/* Macros here mostly to make it easier to track locking behavior */
// #define pfa_trace_locks(M, ...) pfa_trace("PFA_TRACE_LOCKS (%d): " M, task_tgid_vnr(current), ##__VA_ARGS__)
#define pfa_trace_locks(M, ...) 

#define pfa_lock(LOCK) do { \
  pfa_trace_locks("Locking PFA: %s:%d\n", __FILE__, __LINE__); \
  down_write(&pfa_mutex_##LOCK); \
  pfa_trace_locks("Got it!\n"); \
} while(0)

static inline int __pfa_trylock(const char *file, int line, struct rw_semaphore *lock) {
  int res = down_write_trylock(lock);
  if(res)
    pfa_trace_locks("Try Locked PFA: %s:%d\n", file, line);
  // else
  //   pfa_trace_locks("Failed to Lock PFA: %s:%d\n", file, line);

  return res;
}
#define pfa_trylock(LOCK) __pfa_trylock(__FILE__, __LINE__, &pfa_mutex_##LOCK)

#define pfa_unlock(LOCK) do { \
  up_write(&pfa_mutex_##LOCK); \
  pfa_trace_locks("Unlocked PFA: %s:%d\n", __FILE__, __LINE__); \
} while(0)

/* Don't use BUG_ON(!mutex_is_locked...), it breaks in bizzare ways */
#define pfa_assert_lock(LOCK) \
  do { \
    if(!rwsem_is_locked(&pfa_mutex_##LOCK)) \
      panic("pfa_assert_lock"); \
  } while(0)

/* Applies the new remote pte value to the PTEs associated with the evicted page. */
void pfa_epg_apply(struct page *pg);

/* Place a page into the evicted pages list */
void pfa_epg_add(struct page *pg, pmd_t *pmd, pte_t *ptep, pte_t rem_pteval, struct
    vm_area_struct *vma, unsigned long addr);

/* Remove page from the evicted page list without applying it.
 * Note: Safe to call on pages not in the epg list 
 * Returns:
 *  1 if the page was in the epg list 
 *  0 if the page wasn't in the epg list*/
int pfa_epg_drop(struct page *pg);

/* same as pfa_drop_epg but indexed by ptep instead of struct page */
int pfa_epg_drop_ptep(pte_t *ptep);

int pfa_epg_get_cnt(void);

/* initialize the system, only call once!
 * memblade_mac - MAC address for the memory blade to use (configured only once) */
void pfa_init(uint64_t memblade_mac);

/* Evict a page to the pfa. */
void pfa_evict(uintptr_t rpn, phys_addr_t page_paddr);

int64_t pfa_nnew(void);

/* Fetch and report every newpage from PFA.
 * mmap_sem_tsk: Caller may optionally hold exactly one mmap_sem. If it does
 *   hold one, pass that task pfa_tsk_id here, otherwise pass -1.
 * Caller must hold pfa_lock */
int pfa_drain_newq(int mmap_sem_tsk);

/* Provides enough free frames to the PFA to fill it's queues
 * Caller must hold pfa_lock */
void pfa_fill_freeq(void);

/* Do everything that the real PFA HW would do (and hopefully no more) */
int pfa_em(struct mm_struct *mm, uintptr_t addr);

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

static inline pte_t pfa_remote_to_local(pte_t rpte, uintptr_t paddr)
{
  uint64_t lpte = pte_val(rpte);
  // Mask off the pgid
  lpte &= (1 << PFA_PGID_SHIFT) - 1;
  // Move the prot bits into the right place for a local pte
  lpte >>=  PFA_PROT_SHIFT;
  // Mask in the ppn
  lpte |= (paddr & PAGE_MASK) >> 2;
  
  // Clear pgid
  // lpte &= ~(PAGE_MASK);
  // lpte |= paddr & PAGE_MASK;
  return __pte(lpte);
}

/* Retrieve the swp_entry_t from a remote pte */
static inline swp_entry_t pfa_remote_to_swp(pte_t pte)
{
  return pfa_pgid_to_swp((pfa_pgid_t)(pte_val(pte) >> PFA_PGID_SHIFT));
}

static inline pfa_pgid_t pfa_remote_to_pgid(pte_t pte)
{
  return (pfa_pgid_t)(pte_val(pte) >> PFA_PGID_SHIFT);
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

/* initialize the system, only call once!
 * memblade_mac - MAC address for the memory blade to use (configured only once) */
void pfa_init(uint64_t memblade_mac);


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

#endif //ifdef __PFA_H__
