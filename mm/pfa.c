#include <linux/mm.h>
#include <linux/pfa.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include "internal.h"

/* Phyiscal addr for MMIO to pfa */
#define PFA_IO_BASE           0x2000
#define PFA_IO_FREEFRAME           (PFA_IO_BASE)
#define PFA_IO_FREESTAT            (PFA_IO_BASE + 8)
#define PFA_IO_EVICTPAGE           (PFA_IO_BASE + 16)
#define PFA_IO_EVICTSTAT           (PFA_IO_BASE + 24)
#define PFA_IO_NEWPGID             (PFA_IO_BASE + 32)
#define PFA_IO_NEWVADDR            (PFA_IO_BASE + 40)
#define PFA_IO_NEWSTAT             (PFA_IO_BASE + 48)

/* Properties of PFA */
#define PFA_FREE_MAX 64
#define PFA_NEW_MAX PFA_FREE_MAX
#define PFA_EVICT_MAX 1

/* Global var. See pfa.h for details */
struct task_struct *pfa_tsk;

/* After initialization, points to the kernel MMIO addresses for the PFA */
void __iomem *pfa_io_free;
void __iomem *pfa_io_freestat;
void __iomem *pfa_io_evict;
void __iomem *pfa_io_evictstat;
void __iomem *pfa_io_newpgid;
void __iomem *pfa_io_newvaddr;
void __iomem *pfa_io_newstat;

/* Holds every frame (struct page*) that is given to the PFA in FIFO order */
#define PFA_FRAMEQ_MAX (PFA_FREE_MAX + PFA_NEW_MAX)
int pfa_frameq_head = 0;
int pfa_frameq_tail = 0;
int pfa_frameq_size = 0;
struct page* pfa_frameq[PFA_FRAMEQ_MAX] = {NULL};

/* Local Functions */
void pfa_fill_freeq(void);

void pfa_init(void)
{
  /* Register RPFH I/O addr */
  printk("Linux Initializing PFA\n");
  
  /* Setup MMIO */
  pfa_io_free = ioremap(PFA_IO_FREEFRAME, 8);
  pfa_io_freestat = ioremap(PFA_IO_FREESTAT, 8);
  pfa_io_evict = ioremap(PFA_IO_EVICTPAGE, 8);
  pfa_io_evictstat = ioremap(PFA_IO_EVICTSTAT, 8);
  pfa_io_newpgid = ioremap(PFA_IO_NEWPGID, 8);
  pfa_io_newvaddr = ioremap(PFA_IO_NEWVADDR, 8);
  pfa_io_newstat = ioremap(PFA_IO_NEWSTAT, 8);
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(swp_entry_t swp_ent, uintptr_t page_paddr, uintptr_t vaddr)
{
  uint64_t evict_val;
  int mapcount;

  /* Evict Page */
  pfa_trace("Evicting page (vaddr=0x%lx paddr=0x%lx pgid=%d)\n",
      vaddr,
      page_paddr,
      pfa_swp_to_pgid(swp_ent));

#ifdef PFA_DEBUG
  /* I'm not sure if this is possible in Linux, but free frames may end up on
   * the lru lists and get re-selected for eviction. */
  if(pfa_frameq_search(page_paddr)) {
      panic("evicting frame on frameq: paddr=%lx\n", page_paddr);
  }

  /* The PFA will get right-screwy if we evict shared pages. Who knows what
   * chaos might ensue if that happens! */
  mapcount = page_mapcount(phys_to_page(page_paddr));
  if(mapcount > 1) {
    panic("Page (paddr 0x%lx) shared %d times (sharing not supported in pfa)\n",
        page_paddr, mapcount);
  }
#endif

  /* Form the packed eviction value defined in pfa spec */
  evict_val = page_paddr >> PAGE_SHIFT;
  BUG_ON(evict_val >> PFA_EVICT_PGID_SHIFT != 0);
  evict_val |= ((uint64_t)pfa_swp_to_pgid(swp_ent) << PFA_EVICT_PGID_SHIFT);

  writeq(evict_val, pfa_io_evict);
 
  /* Wait for completion */
  while(readq(pfa_io_evictstat) < PFA_EVICT_MAX) {}
}

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(struct page* pg)
{
  pfa_trace("Adding 0x%llx to freelist (mapcount %d)\n", page_to_phys(pg), page_mapcount(pg));
  writeq(page_to_phys(pg), pfa_io_free);
  pfa_frameq_push(pg);
}

int64_t pfa_nnew(void)
{
  return readq(pfa_io_newstat);
}

#if 0
/* This version drains the newq but doesn't do anything.
 * useful for testing */
void pfa_new(void)
{
  void *vaddr = NULL;
  pfa_pgid_t pgid = 0;
  struct page* frame;

  BUG_ON(readq(pfa_io_newstat) == 0);
  vaddr = (void*)readq(pfa_io_newvaddr);
  pgid = readq(pfa_io_newpgid);
  frame = pfa_frameq_pop();

  printk("New Page: pgid=%d, vaddr=%p\n", pgid, vaddr);
  return;
}
#endif

/* Process one entry from the newq.
 * Assumes there is at least one entry in newq (check NEWSTAT first). 
 * Caller must down pfa_tsk->mm->mmap_sem
 *
 * Note: Much of this code is stolen from handle_mm_fault */
static void pfa_new(void)
{
  int ret;
  struct mm_struct *mm;
  /* These flags are coppied from do_page_fault, I'm not 100% on them */
  unsigned int flags = FAULT_FLAG_ALLOW_RETRY | 
                       FAULT_FLAG_KILLABLE |
                       FAULT_FLAG_USER;
	struct vm_fault vmf;
  swp_entry_t entry;
  pfa_pgid_t new_pgid;

  pgd_t *pgd;
  p4d_t *p4d;

#ifdef PFA_DEBUG
  BUG_ON(readq(pfa_io_newstat) == 0);
#endif

  /* Get the new page info from newq and frameq */
  vmf.address = readq(pfa_io_newvaddr) & PAGE_MASK;
  new_pgid = (pfa_pgid_t)readq(pfa_io_newpgid);
  pfa_trace("Fetching New Page: id=%d\n", new_pgid);
  
  entry = pfa_pgid_to_swp(new_pgid);

  BUG_ON(pfa_tsk == NULL);
  mm = pfa_tsk->mm;
  
  if(!mm) {
    panic("Trying to bookkeep PFA without an mm\n");
  }
  vmf.vma = find_vma(mm, vmf.address);
  BUG_ON(!vmf.vma);
  /* The actual check in do_page_fault is more complicated than this
   * I'm assuming swap-triggered page faults always satisfy this */
  BUG_ON(!(vmf.vma->vm_start <= vmf.address));

  /* XXX gfp_mask gets set in normal swap path but seems unused. */
  vmf.flags = flags;
  vmf.pgoff = linear_page_index(vmf.vma, vmf.address);

  /* Page-table walk to get pte. 
   * Much error-checking elided. Look at __handle_mm_fault and
   * _handle_pte_fault for more realistic error checking. */
	pgd = pgd_offset(mm, vmf.address);
	p4d = p4d_alloc(mm, pgd, vmf.address);
  BUG_ON(!p4d);
	vmf.pud = pud_alloc(mm, p4d, vmf.address);
  BUG_ON(!vmf.pud);
	vmf.pmd = pmd_alloc(mm, vmf.pud, vmf.address);
  BUG_ON(!vmf.pmd);
  vmf.pte = pte_offset_map(vmf.pmd, vmf.address);
  vmf.orig_pte = *vmf.pte;
  BUG_ON(pte_none(vmf.orig_pte));

  /* Put the swap entry back into the PTE so we can use the unmodified
   * do_swap_page 
   * NOTE: this clears _PAGE_FETCHED as well */
  vmf.orig_pte = swp_entry_to_pte(entry);
	set_pte_at(mm, vmf.address, vmf.pte, vmf.orig_pte);

  ret = do_swap_page(&vmf);
  BUG_ON(ret & VM_FAULT_ERROR);

  return;
}

void pfa_drain_newq(void)
{
  uint64_t nnew = readq(pfa_io_newstat);
  if(nnew) 
    pfa_trace("Draining %lld items from newq\n", nnew);

  while(nnew)
  {
    pfa_new(); 
    nnew--;
  }
}

void pfa_fill_freeq(void)
{
  struct page* pg;

  uint64_t nframe;
  
  nframe = readq(pfa_io_freestat);

  while(nframe) {
    /* This might block or trigger swapping which would be bad if we call
     * pfa_fill_new from the pageout path... */
    pg = alloc_page(GFP_HIGHUSER_MOVABLE);

#ifdef PFA_DEBUG
    /* Don't want pages with user mappings going out, this is just me being
     * paranoid (alloc_page really shouldn't) */
    if(unlikely(page_mapcount(pg) > 0)) {
      panic("newly alloced page has nonzero mapcount (%d)!\n", page_mapcount(pg));
    }
#endif

    pfa_free(pg);
    nframe--;
  }
}

/* Right now, we don't handle any fault, just report and return an error */
int pfa_handle_fault(struct vm_fault *vmf)
{
  pfa_trace("Page fault received on remote page (vaddr=0x%lx)\n",
      vmf->address & PAGE_MASK);

  if(readq(pfa_io_freestat) == PFA_FREE_MAX) {
    /* FreeQ Empty */
    pfa_trace("FreeQ Empty!\n");
    pfa_fill_freeq();
    pfa_trace("Filled FreeQ\n");
  }
  
  /* Probably don't need this anymore since we pro-actively drain newq on
   * every page fault early on (in do_page_fault) */
  if(pfa_nnew() == PFA_NEW_MAX) {
    /* NewQ Full */
    pfa_trace("NewQ full!\n");
    pfa_drain_newq();
    pfa_trace("Drained NewQ\n");
  }

  return 0;
}

void pfa_frameq_push(struct page *frame)
{
  BUG_ON(pfa_frameq_size == PFA_FRAMEQ_MAX);

#ifdef PFA_DEBUG
  BUG_ON(pfa_frameq_search(page_to_phys(frame)));
#endif

  pfa_frameq[pfa_frameq_head] = frame;

  pfa_frameq_head = (pfa_frameq_head + 1) % PFA_FRAMEQ_MAX;
  pfa_frameq_size++;

  return;
}

struct page* pfa_frameq_pop(void)
{
  struct page *ret;

  BUG_ON(pfa_frameq_size == 0);
  ret = pfa_frameq[pfa_frameq_tail];
  BUG_ON(ret == NULL);
  
  pfa_frameq[pfa_frameq_tail] = NULL;

  pfa_frameq_tail = (pfa_frameq_tail + 1) % PFA_FRAMEQ_MAX;
  pfa_frameq_size--;

  return ret;
}

int pfa_frameq_search(uintptr_t paddr)
{
  int i;
  for(i = pfa_frameq_tail; i != pfa_frameq_head; i = (i + 1) % PFA_FRAMEQ_MAX)
  {
    if(pfa_frameq[i] == NULL) {
      panic("Invalid frameq entry\n");
    }
    if(page_to_phys(pfa_frameq[i]) == paddr) {
      return 1;
    }
  }

  return 0;
}

void pfa_set_tsk(struct task_struct *tsk)
{
  if(pfa_tsk != NULL) {
    panic("Resetting the pfa_tsk not currently supported\n");
  }
  pfa_tsk = tsk;
  return;
}

