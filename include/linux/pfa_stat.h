#ifndef _PFA_STAT_H
#define _PFA_STAT_H
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

/* Statistics
 * All times are measured in terms of CPU clock cycles as reported by
 * pfa_stat_clock(). DON'T USE get_cycles()!! */
typedef struct pfa_stat {
  /* Cycles spent in bookkeeping code (calls to drain_newq() or do_swap_page) */
  atomic64_t t_bookkeeping;

  /* Cycles waiting for writes to the backing store (e.g. pfa_evict or
   * rswap_store). */
  atomic64_t t_rmem_write;

  /* Cycles waiting for reads from the backing store (rswap_load).
   *
   * NOTE: this will always be 0 when using the PFA (can't be measured in SW)*/
  atomic64_t t_rmem_read;

  /* Total number of page faults (swapping or otherwise) */
  atomic64_t n_fault;

  /* Total time spent in the page-fault handler */
  atomic64_t t_fault;

  /* Total number of page faults due to swapped-out pages (same as major plus
   * minor faults). Should be 0 when PFA enabled. */
  atomic64_t n_swapfault;

  /* Total number of faults due to full queues */
  atomic64_t n_pfa_fault;

  /* The total number of times the newq was drained pre-maturely for correctness.
   * The most common cause is write-protected pages being faulted in. */
  atomic64_t n_early_newq;

  /* The total number of pages evicted */
  atomic64_t n_evicted;

  /* The total number of pages fetched (should be the same as "major
   * pagefaults" when the PFA is disabled. */
  atomic64_t n_fetched;

  /* Time spent in kpfad (doesn't include overhead due to context switch) */
  atomic64_t t_kpfad;

  /* Number of invocations of kpfad (regardless of runtime or lock contention) */
  atomic64_t n_kpfad;

  /* Time that stat recording started for the most recent task. */
  atomic64_t t_start;

  /* Total runtime of the last registered task */
  atomic64_t t_run;

} pfa_stat_t;

/* Global stats struct (use atomic_* to access feilds) */
extern pfa_stat_t pfa_stats;

extern struct task_struct *pfa_stat_tsk;
extern uint64_t pfa_pfstart;
extern uintptr_t pfa_last_vaddr;

/* Add or set "value" to "feild" of global pfa_stat_t for task "tsk". Record
 * for alltasks if tsk==NULL.
 *
 * Use the pfa_stat_add/set version, not the _ version */
static inline void _pfa_stat_add(atomic64_t *feild, int64_t value, struct task_struct *tsk)
{
  if(tsk == pfa_stat_tsk || tsk == NULL) {
    atomic64_add(value, feild);
  }
}

static inline void _pfa_stat_set(atomic64_t *feild, int64_t value, struct task_struct *tsk)
{
  if(tsk == pfa_stat_tsk || tsk == NULL) {
    atomic64_set(feild, value);
  }
}
#define pfa_stat_add(feild, value, tsk) _pfa_stat_add(&(pfa_stats.feild), value, tsk) 
#define pfa_stat_set(feild, value, tsk) atomic64_set(&(pfa_stats.feild), value); 

/* Get CPU clock cycle (different than Linux get_cycles()) 
 * NOTE: Use this, DON'T USE get_cycles()!!!
 * Linux's get_cycles() uses rdtime which is a trap on rocket (i.e. slow) */
#ifdef CONFIG_RISCV
static inline uint64_t pfa_stat_clock(void)
{
	uint64_t n;

	__asm__ __volatile__ (
		"rdcycle %0"
		: "=r" (n));
	return n;
}
#else
static inline uint64_t pfa_stat_clock(void)
{
  /* This is rdtsc on x86 */
  return get_cycles();
}
#endif

/* Call once at boot time. */
void pfa_stat_init(void);

/* Clears statistics and assigns new task to watch.
 * You may provide NULL for tsk, in which case stats collection will be
 * disabled.
 */
void pfa_stat_reset(struct task_struct *tsk);

extern int pfa_pflat_state;

#ifdef CONFIG_PFA_PFLAT
static inline void pfa_pflat_set_vaddr(uintptr_t vaddr, struct vm_area_struct *vma)
{
  if(pfa_pflat_state == 0 && vma->vm_mm->owner == pfa_stat_tsk) {
    pfa_last_vaddr = vaddr;
  }
}

static inline void pfa_pflat_set_start(uintptr_t vaddr)
{
  if(pfa_pflat_state == 1 &&
     current == pfa_stat_tsk &&
     pfa_pfstart == 0 &&
     vaddr == pfa_last_vaddr) {
    pfa_pfstart = pfa_stat_clock();
  }
}
#else

#define pfa_pflat_set_vaddr(vaddr, vma)
#define pfa_pflat_set_start(vaddr)
#endif

#endif

