#ifndef _PFA_STAT_H
#define _PFA_STAT_H
#include <linux/types.h>
#include <linux/sched.h>

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
   * NOTE: this will always be 0 when using the PFA */
  atomic64_t t_rmem_read;

  /* Total number of page faults (swapping or otherwise) */
  atomic64_t n_fault;

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

  /* The total number of pages fetched */
  atomic64_t n_fetched;

  /* Time spent in kpfad (doesn't include overhead due to context switch) */
  atomic64_t t_kpfad;

} pfa_stat_t;

/* Add "value" to "feild" of global pfa_stat_t for task "tsk" 
 * NOTE: Right now this just filters by tsk, eventually we might
 * have per-task statistics. */
#define pfa_stat_add(feild, value, tsk)           \
  do {                                            \
    if(tsk == pfa_stat_tsk) {                     \
      atomic64_add(value, &(pfa_stats.feild));    \
    }                                             \
  } while(0)

/* Global stats struct (use atomic_* to access feilds) */
extern pfa_stat_t pfa_stats;

extern struct task_struct *pfa_stat_tsk;

/* Get CPU clock cycle (different than Linux get_cycles()) 
 * NOTE: Use this, DON'T USE get_cycles()!!!
 * Linux's get_cycles() uses rdtime which is a trap on rocketchip (i.e. slow) */
static inline uint64_t pfa_stat_clock(void)
{
	uint64_t n;

	__asm__ __volatile__ (
		"rdcycle %0"
		: "=r" (n));
	return n;
}

/* Call once at boot time. */
void pfa_stat_init(void);

/* Clears statistics and assigns new task to watch.
 * You may provide NULL for tsk, in which case stats collection will be
 * disabled.
 */
void pfa_stat_reset(struct task_struct *tsk);

#endif
