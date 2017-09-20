#include <linux/mm.h>
#include <linux/pfa.h>
#include <linux/io.h>
#include <linux/gfp.h>

/* Phyiscal addr for MMIO to pfa */
#define PFA_IO_BASE           0x2000
#define PFA_IO_FREEFRAME           (PFA_IO_BASE)
#define PFA_IO_FREESTAT            (PFA_IO_BASE + 8)
#define PFA_IO_EVICTPAGE           (PFA_IO_BASE + 16)
#define PFA_IO_EVICTSTAT           (PFA_IO_BASE + 24)
#define PFA_IO_NEWPAGE             (PFA_IO_BASE + 32)
#define PFA_IO_NEWSTAT             (PFA_IO_BASE + 40)

/* Properties of PFA */
#define PFA_FREE_MAX 64
#define PFA_NEW_MAX PFA_FREE_MAX
#define PFA_EVICT_MAX 1

/* After initialization, points to the kernel MMIO addresses for the PFA */
void __iomem *pfa_io_free;
void __iomem *pfa_io_freestat;
void __iomem *pfa_io_evict;
void __iomem *pfa_io_evictstat;
void __iomem *pfa_io_new;
void __iomem *pfa_io_newstat;

/* Used for registering a process with the PFA subsystem.
 * Only one process an use the PFA for now */
pid_t pfa_pid = -1;
unsigned long pfa_addr = 0;

/* Local Functions */
void pfa_fill_freeq(void);

void pfa_init(void)
{
  /* Register RPFH I/O addr */
  printk("Linux Initializing PFA\n");
  
  pfa_io_free = ioremap(PFA_IO_FREEFRAME, 8);
  pfa_io_freestat = ioremap(PFA_IO_FREESTAT, 8);
  pfa_io_evict = ioremap(PFA_IO_EVICTPAGE, 8);
  pfa_io_evictstat = ioremap(PFA_IO_EVICTSTAT, 8);
  pfa_io_new = ioremap(PFA_IO_NEWPAGE, 8);
  pfa_io_newstat = ioremap(PFA_IO_NEWSTAT, 8);
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(uintptr_t vaddr, uintptr_t page_paddr)
{
   /* Evict Page */
  pfa_trace("Evicting page 0x%lx at 0x%lx\n", vaddr, page_paddr);
  writeq(vaddr, pfa_io_evict);
  writeq(page_paddr, pfa_io_evict);
 
  /* Wait for completion */
  while(readq(pfa_io_evict) != 0) {}

  /* XXX not sure if I really want to do this here long-term */
  /* Add free frames */
  pfa_fill_freeq();
}

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(uintptr_t pte_paddr)
{
  pfa_trace("Adding 0x%lx to freelist\n", pte_paddr);
  writeq(pte_paddr, pfa_io_free);
}

void pfa_new(void)
{
  uint64_t nnew = readq(pfa_io_newstat);
  while(nnew)
  {
    uintptr_t newpage = readq(pfa_io_new);
    pfa_trace("New Page fetched: 0x%lx\n", newpage);
    nnew--;
  }
}

void pfa_fill_freeq(void) {
  struct page* pg;

  uint64_t nnew;
  
  nnew = readq(pfa_io_freestat);

  while(nnew) {
    /* This might block or trigger swapping which would be bad if we call
     * pfa_fill_new from the pageout path... */
    pg = alloc_page(GFP_HIGHUSER_MOVABLE);
    pfa_free(page_to_phys(pg));
    nnew--;
  }
}

/* Right now, we don't handle any fault, just report and return an error */
int pfa_handle_fault(struct vm_fault *vmf)
{
  pfa_trace("Page fault received on remote page\n");

  if(readq(pfa_io_freestat) == PFA_FREE_MAX) {
    /* FreeQ Empty */
    pfa_trace("FreeQ Empty!\n");
    pfa_fill_freeq();
    pfa_trace("Filled FreeQ\n");
    return 0;
  } else if(readq(pfa_io_newstat) == PFA_NEW_MAX) {
    /* NewQ Full */
    pfa_trace("NewQ full!\n");
    pfa_new();
    pfa_trace("Drained NewQ\n");
    return 0;
  } else {
    pfa_trace("WARNING: Page fault on remote page but all queues are healthy.\n");
    return VM_FAULT_SIGBUS;
  }

  return 0;
}
