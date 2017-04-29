#include<linux/syscalls.h>
#include<asm/unistd.h>

#include<linux/sched.h>

/* Used for registering a process with the PFA subsystem.
 * Only one process an use the PFA for now */
pid_t pfa_pid;
unsigned long pfa_addr;

/* ugly hack to initialize system, I'll figure out a real way later */
bool pfa_initp = false;

/* Phyiscal addr for MMIO to pfa */
#define PFA_IO_BASE           0x2000
#define PFA_IO_FREE           (PFA_IO_BASE)
#define PFA_IO_EVICT          (PFA_IO_BASE + 8)

/* After initialization, points to the kernel MMIO addresses for the PFA */
void __iomem *pfa_io_free;
void __iomem *pfa_io_evict;

/* Get the paddr of PTE for the provided vaddr */
static unsigned long pfa_get_pte_paddr(struct mm_struct *mm, unsigned long addr);

/* initialize the system, only call once! */
void pfa_init(void);

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(unsigned long ptep);

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(unsigned long pfn);

/* Generic PFA syscall, used for all sorts of communication 
 * Right now it will manually evict the page at "address" 
 */
SYSCALL_DEFINE1(pfa, unsigned long, address)
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
  pfa_addr = address;

  /* get the pte in a locked state (since we're messing with it) */
  ptep = get_locked_pte(mm, address, &ptl); 

  /* Strictly speaking, this function is a bit redundant, but I'm to lazy to
   * figure out the correct vaddr_to_paddr() function */
  pte_paddr = pfa_get_pte_paddr(mm, address);
  if(ptep == 0) {
    printk("pfa syscall failure\n");
    return 0;
  }

  /* Evict the page and give it's freshly vacated page-frame to the PFA */
  pfa_evict(pte_paddr);
  pfa_free(pte_val(*ptep) >> PAGE_SHIFT);

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
void pfa_free(unsigned long pfn)
{
  printk("Providing page %p to pfa\n", (void*)(pfn << PAGE_SHIFT));
  writel((uint32_t)(pfn << PAGE_SHIFT), pfa_io_free);
}

/* Get the PTE for the provided address
 * This seems to be a different procedure than __handle_mm_fault uses,
 * hopefully it continues to work...
 */
static unsigned long pfa_get_pte_paddr(struct mm_struct *mm, unsigned long addr)
{
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd;

  pgd = pgd_offset(mm, addr);
  if (pgd_none(*pgd) || pgd_bad(*pgd)) {
    printk("bad pgd\n");
    goto err;
  }
   
  pud = pud_offset(pgd, addr);
  if (pud_none(*pud) || pud_bad(*pud)) {
    printk("bad pud\n");
    goto err;
  }

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd)) {
    printk("bad pmd\n");
    goto err;
  }

  /* add pte offset to physical addr of pmd */
  return (pmd_val(*pmd) + pte_index(addr));

err:
  printk("Couldn't find pte of addr: %lx\n", addr);
  return 0;
}


#if 0
/* Send a page out to remote memory 
 * Call "pfa_wait()" to wait for completion. */ 
static void pfa_evict(pte_t *ptep, int64_t vaddr) {
	pfa_req_t req;
  
  req.pte_paddr = pfa_vTop(ptep);
  req.vaddr = vaddr;
  req.paddr = ;
  req.pid = pfa_pid;
  req.op = pfa_evict;

}

static uint64_t pfa_vTop(uint64_t vaddr) {
	uint64_t page_addr = pte_val(*pte) & PAGE_MASK;
	uint64_t page_offset = vaddr & ~PAGE_MASK;
  return page_addr | page_offset;
}

/* Send a command to the pfa */
static void pfa_send_request(void const *page, rpfh_op op) {
  pte_t *page_pte = walk((uintptr_t) page);

  rpfh_request req;
  req.pte_paddr = va2pa(page_pte);
  req.vaddr = (uint64_t) page;
  req.paddr = __pfn_to_phys(pte_pfn(*ptep));
  req.pid = 0;
  req.op = op;

  volatile uint64_t req_addr = (uint64_t) &req;
  volatile static uint64_t *rpfh_addr = (uint64_t *) RPFH_IO_ADDR;
  *rpfh_addr = req_addr;
  mb();
}
#endif
