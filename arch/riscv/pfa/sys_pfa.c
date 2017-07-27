
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
#define PFA_IO_FREEFRAME           (PFA_IO_BASE)
#define PFA_IO_EVICTPAGE           (PFA_IO_BASE + 8)
#define PFA_IO_NEWPAGE             (PFA_IO_BASE + 16)

/* After initialization, points to the kernel MMIO addresses for the PFA */
void __iomem *pfa_io_free;
void __iomem *pfa_io_evict;
void __iomem *pfa_io_new;

/* initialize the system, only call once! */
void pfa_init(void);

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(uintptr_t vaddr, uintptr_t pte_paddr);

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(unsigned long pte_paddr);

/* Fetch and report every newpage from PFA */
void pfa_new(void);

/* Translate any virtual address to it's physical address 
 * note the kernel virt_to_phys only works for kernel addresses
 * pte: PTE of vaddr to translate
 * vaddr: virtual address to translate
 */
uintptr_t pfa_vaddr_to_paddr(pte_t pte, uintptr_t vaddr)
{
  return (pte_pfn(pte) << PAGE_SHIFT) +
         (vaddr & ~(~0ul << PAGE_SHIFT));
}

/* Generic PFA syscall, used for all sorts of communication 
 * Right now it will manually evict the page at "address" 
 *
 * passing NULL for vaddr will drain the newpage queue
 */
SYSCALL_DEFINE1(pfa, unsigned long, pg_vaddr)
{
  struct task_struct *tsk;
  struct mm_struct *mm;
  unsigned long pg_paddr, pte_paddr; //paddr
  pid_t pid;
  pte_t *pg_ptep; /* pointer to the page's pte */
  spinlock_t *pg_ptl;
  
  if(!pfa_initp) {
    pfa_initp = true;
    pfa_init();
  }

  if(pg_vaddr == 0) {
    pfa_new();
    return 1;
  }

  tsk = current;
  mm = tsk->mm;
  pid = task_tgid_vnr(current);

  /* get the pte in a locked state (since we're messing with it) */
  pg_ptep = get_locked_pte(mm, pg_vaddr, &pg_ptl); 
  pg_paddr = pfa_vaddr_to_paddr(*pg_ptep, (uintptr_t)pg_vaddr);
  
  /* Get address info for the page's pte itself */
  pte_paddr = virt_to_phys(pg_ptep);
  
  printk("pfa syscall: vaddr=0x%lx\tpaddr=0x%lx\tpte=0x%lx\tpte_paddr=0x%lx\tpid=%d\n",
      pg_vaddr,
      pg_paddr,
      *pg_ptep,
      pte_paddr,
      pid);

#ifndef USE_PFA
  /* This is a minimal test that doesn't involve the actual PFA */
  pfa_pid = pid;
  pfa_addr = pg_vaddr;

  /* Clear the present bit to trick the system into "swapping" it back in */
  set_pte(pg_ptep, pte_clear_present(*ptep));

#else
  /* This version uses the actual PFA */
  /* Evict the page and give it's freshly vacated page-frame to the PFA */
  pfa_evict(pg_vaddr, pte_paddr);
  pfa_free(pg_paddr);
#endif

  /* Unlock PTE, a little scary but I don't know how to detect if someone
   * is trying to mess with it and we can't just hang if they do*/
  pte_unmap_unlock(pg_ptep, pg_ptl);
  /* pte_unmap_unlock(pte_ptep, pte_ptl); */

  return 1;
}

void pfa_init(void)
{
  pfa_initp = true;
  /* Register RPFH I/O addr 
   * XXX PFA: I'm gonna have to figure out how to initialize this properly. */
  printk("Linux Initializing PFA\n");
  
  pfa_io_free = ioremap(PFA_IO_FREEFRAME, 8);
  pfa_io_evict = ioremap(PFA_IO_EVICTPAGE, 8);
  pfa_io_new = ioremap(PFA_IO_NEWPAGE, 8);
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(uintptr_t vaddr, uintptr_t pte_paddr)
{
   /* Evict Page */
  printk("Evicting page 0x%lx\n", vaddr);
  writeq(vaddr, pfa_io_evict);
  writeq(pte_paddr, pfa_io_evict);
 
  /* Wait for completion */
  printk("Polling for completion\n");
  while(readq(pfa_io_evict) != 0) {}
  printk("Eviction complete!\n");
}

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(uintptr_t pte_paddr)
{
  writeq(pte_paddr, pfa_io_free);
}

void pfa_new(void)
{
  uintptr_t newpage = readq(pfa_io_new);
  while(newpage != 0)
  {
    printk("New Page fetched: 0x%lx\n", newpage);
    newpage = readq(pfa_io_new);
  }
}
