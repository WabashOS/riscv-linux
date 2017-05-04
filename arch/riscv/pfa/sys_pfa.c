
#include<linux/syscalls.h>
#include<asm/unistd.h>

#include<linux/sched.h>

/* Comment this out to emulate the PFA with protection bits.
 * Leave uncommented to use the actual PFA */ 
#define USE_PFA

/* Used for registering a process with the PFA subsystem.
 * Only one process an use the PFA for now */
pid_t pfa_pid = -1;
unsigned long pfa_addr = 0;

/* ugly hack to initialize system, I'll figure out a real way later */
bool pfa_initp = false;

/* Phyiscal addr for MMIO to pfa */
#define PFA_IO_BASE           0x2000
#define PFA_IO_FREE           (PFA_IO_BASE)
#define PFA_IO_EVICT          (PFA_IO_BASE + 8)

/* After initialization, points to the kernel MMIO addresses for the PFA */
void __iomem *pfa_io_free;
void __iomem *pfa_io_evict;

/* initialize the system, only call once! */
void pfa_init(void);

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(unsigned long pte_paddr);

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(unsigned long pte_paddr);

/* Generic PFA syscall, used for all sorts of communication 
 * Right now it will manually evict the page at "address" 
 */
SYSCALL_DEFINE1(pfa, unsigned long, pg_vaddr)
{
  struct task_struct *tsk;
  struct mm_struct *mm;
  unsigned long pte_paddr; //paddr of pte
  pte_t *ptep;
  spinlock_t *ptl;
  
  printk("Entering pfa syscall\n");

  if(!pfa_initp) {
    pfa_initp = true;
    pfa_init();
  }

  tsk = current;
  mm = tsk->mm;

  /* Register the PID and the Addr */
	pfa_pid = task_tgid_vnr(current);
  pfa_addr = pg_vaddr;

  /* get the pte in a locked state (since we're messing with it) */
  ptep = get_locked_pte(mm, pg_vaddr, &ptl); 
  pte_paddr = virt_to_phys(ptep);

#ifndef USE_PFA
  /* This is a minimal test that doesn't involve the actual PFA */
  /* Clear the present bit to trick the system into "swapping" it back in */
  set_pte(ptep, pte_clear_present(*ptep));
#else
  /* Evict the page and give it's freshly vacated page-frame to the PFA */
  /* pfa_evict(pte_paddr); */
  /* pfa_free(pte_paddr); */
#endif

  /* Unlock PTE, a little scary but I don't know how to detect if someone
   * is trying to mess with it and we can't just hang if they do*/
  pte_unmap_unlock(ptep, ptl);

  printk("Registered vaddr %lx for pid %d\n", pfa_addr, pfa_pid);
  return 1;
}

void pfa_init(void)
{
  pfa_initp = true;
  /* Register RPFH I/O addr 
   * XXX PFA: I'm gonna have to figure out how to initialize this properly. */
  printk("Linux Initializing PFA\n");
  /* For some reason, we need 4 byte values here, problem with qemu */
  pfa_io_free = ioremap(PFA_IO_FREE, 4);
  pfa_io_evict = ioremap(PFA_IO_EVICT, 4);
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(unsigned long pte_paddr)
{
   /* Evict Page */
  printk("Evicting a page\n");
  writel((uint32_t)pte_paddr, pfa_io_evict);
 
  /* Wait for completion */
  printk("Polling for completion\n");
  while(readl(pfa_io_evict) != 0) {}
  printk("Eviction complete!\n");
}

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(unsigned long pte_paddr)
{
  writel((uint32_t)pte_paddr, pfa_io_free);
}
