
#include<linux/syscalls.h>
#include<asm/unistd.h>

#include<linux/sched.h>
#include<linux/pfa.h>

/* Generic PFA syscall, used for all sorts of communication 
 * Right now it will manually evict the page at "address" 
 *
 * passing NULL for vaddr will drain the newpage queue
 */
SYSCALL_DEFINE1(pfa, unsigned long, pg_vaddr)
{
#ifndef USE_PFA
  printk("pfa syscall: PFA not enabled, doing nothing.\n");
#else
  struct task_struct *tsk;
  struct mm_struct *mm;
  unsigned long pg_paddr, pte_paddr; //paddr
  pte_t *pg_ptep; /* pointer to the page's pte */
  spinlock_t *pg_ptl;
  
  pfa_init();

  if(pg_vaddr == 0) {
    pfa_new();
    return 1;
  }

  tsk = current;
  mm = tsk->mm;

  /* get the pte in a locked state (since we're messing with it) */
  pg_ptep = get_locked_pte(mm, pg_vaddr, &pg_ptl); 
  pg_paddr = pfa_vaddr_to_paddr(*pg_ptep, (uintptr_t)pg_vaddr);
  
  /* Get address info for the page's pte itself */
  pte_paddr = virt_to_phys(pg_ptep);
  
  printk("pfa syscall: vaddr=0x%lx\tpaddr=0x%lx\tpte=0x%lx\tpte_paddr=0x%lx\n",
      pg_vaddr,
      pg_paddr,
      pte_val(*pg_ptep),
      pte_paddr);

  /* This version uses the actual PFA */
  /* Evict the page and give it's freshly vacated page-frame to the PFA */
  pfa_evict(pg_vaddr, pte_paddr);
  pfa_free(pg_paddr);

  /* Unlock PTE, a little scary but I don't know how to detect if someone
   * is trying to mess with it and we can't just hang if they do*/
  pte_unmap_unlock(pg_ptep, pg_ptl);

#endif

  return 1;
}
