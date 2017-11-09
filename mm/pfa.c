#include <linux/mm.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kobject.h>
#include <linux/timex.h>
#include <linux/pfa.h>
#include <linux/pfa_stat.h>
#include "internal.h"

/* Phyiscal addr for MMIO to pfa */
/* #define PFA_IO_BASE           0x2000 */
#define PFA_IO_BASE                0x10017000 
#define PFA_IO_FREEFRAME           (PFA_IO_BASE)
#define PFA_IO_FREESTAT            (PFA_IO_BASE + 8)
#define PFA_IO_EVICTPAGE           (PFA_IO_BASE + 16)
#define PFA_IO_EVICTSTAT           (PFA_IO_BASE + 24)
#define PFA_IO_NEWPGID             (PFA_IO_BASE + 32)
#define PFA_IO_NEWVADDR            (PFA_IO_BASE + 40)
#define PFA_IO_NEWSTAT             (PFA_IO_BASE + 48)
#define PFA_IO_INITMEM             (PFA_IO_BASE + 56)

/* Properties of PFA */
#define PFA_FREE_MAX 64
#define PFA_NEW_MAX PFA_FREE_MAX
#define PFA_EVICT_MAX 1

DEFINE_MUTEX(pfa_mutex);

/* sysfs stuff */
ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute pfa_sysfs_tsk = __ATTR(pfa_tsk, 0660, pfa_sysfs_show_tsk, pfa_sysfs_store_tsk);

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
void __iomem *pfa_io_initmem;

/* Holds every frame (struct page*) that is given to the PFA in FIFO order */
#define PFA_FRAMEQ_MAX (PFA_FREE_MAX + PFA_NEW_MAX)
int pfa_frameq_head = 0;
int pfa_frameq_tail = 0;
int pfa_frameq_size = 0;
struct page* pfa_frameq[PFA_FRAMEQ_MAX] = {NULL};

/* kpfad settings */
struct task_struct *kpfad_tsk = NULL;
atomic64_t kpfad_sleeptime = ATOMIC_INIT(10000); /* how long to sleep (in us)*/
/* How flexible (in us) to be in re-scheduling */
#define KPFAD_SLEEP_FLEX 5000

/* Local Functions */
/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
static void pfa_free(struct page *pg);

/* PFA management daemon. Mostly drains newq and fills freeq. */
static int kpfad(void *p);

void pfa_init(void)
{
  struct page *pfa_scratch;

  printk("Linux Initializing PFA\n");

  /* Create sysfs interface
   * Don't fail on errors, User won't be able to use PFA, but we don't need
   * to crash the kernel either */
    if(sysfs_create_file(mm_kobj, &pfa_sysfs_tsk.attr) != 0)
          pr_err("Failed to create sysfs entries\n");
  
  /* Setup MMIO */
  pfa_io_free = ioremap(PFA_IO_FREEFRAME, 8);
  pfa_io_freestat = ioremap(PFA_IO_FREESTAT, 8);
  pfa_io_evict = ioremap(PFA_IO_EVICTPAGE, 8);
  pfa_io_evictstat = ioremap(PFA_IO_EVICTSTAT, 8);
  pfa_io_newpgid = ioremap(PFA_IO_NEWPGID, 8);
  pfa_io_newvaddr = ioremap(PFA_IO_NEWVADDR, 8);
  pfa_io_newstat = ioremap(PFA_IO_NEWSTAT, 8);
  pfa_io_initmem = ioremap(PFA_IO_INITMEM, 8);

  /* Provide a scratch area to the PFA 
   * We never free this page after allocating */
  pfa_scratch = alloc_page(GFP_KERNEL | __GFP_COLD);
  writeq(page_to_phys(pfa_scratch), pfa_io_initmem); 

  return;
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(swp_entry_t swp_ent, uintptr_t page_paddr, uintptr_t vaddr)
{
  uint64_t evict_val;
  int mapcount;
  uint64_t start;

  /* Evict Page */
  pfa_trace("Evicting page (vaddr=0x%lx) (paddr=0x%lx) (pgid=%d)\n",
      vaddr,
      page_paddr,
      pfa_swp_to_pgid(swp_ent));

#ifdef PFA_DEBUG
  /* I'm not sure if this is possible in Linux, but free frames may end up on
   * the lru lists and get re-selected for eviction. */
  if(pfa_frameq_search(page_paddr)) {
      panic("Evicting frame on frameq: (paddr=0x%lx)\n", page_paddr);
  }

  /* The PFA will get right-screwy if we evict shared pages. Who knows what
   * chaos might ensue if that happens! */
  mapcount = page_mapcount(phys_to_page(page_paddr));
  if(mapcount > 1) {
    panic("Page (paddr=0x%lx) shared %d times (sharing not supported in pfa)\n",
        page_paddr, mapcount);
  }
#endif

  /* Form the packed eviction value defined in pfa spec */
  evict_val = page_paddr >> PAGE_SHIFT;
  BUG_ON(evict_val >> PFA_EVICT_PGID_SHIFT != 0);
  evict_val |= ((uint64_t)pfa_swp_to_pgid(swp_ent) << PFA_EVICT_PGID_SHIFT);

  start = pfa_stat_clock();
  writeq(evict_val, pfa_io_evict);
 
  /* Wait for completion */
  while(readq(pfa_io_evictstat) < PFA_EVICT_MAX) {}
  pfa_stat_add(t_rmem_write, pfa_stat_clock() - start, pfa_get_tsk());
}

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
static void pfa_free(struct page* pg)
{
  pfa_trace("Adding (paddr=0x%lx) to freelist\n", (unsigned long)page_to_phys(pg));
  writeq(page_to_phys(pg), pfa_io_free);
  pfa_frameq_push(pg);
}

int64_t pfa_nnew(void)
{
  return readq(pfa_io_newstat);
}

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
  pfa_trace("Fetching New Page: (pgid=%d)\n", new_pgid);
  
  entry = pfa_pgid_to_swp(new_pgid);

  BUG_ON(pfa_tsk == NULL);
  mm = pfa_tsk->mm;
  BUG_ON(!mm);
  
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
  uint64_t nnew;
  uint64_t cycles = pfa_stat_clock();

  pfa_assert_lock();

  nnew = readq(pfa_io_newstat);
  if(nnew) 
    pfa_trace("Draining %lld items from newq\n", nnew);

  pfa_stat_add(n_fetched, nnew, pfa_get_tsk());
  while(nnew)
  {
    pfa_new(); 
    nnew--;
  }

  pfa_stat_add(t_bookkeeping, pfa_stat_clock() - cycles, pfa_tsk);
}

void pfa_fill_freeq(void)
{
  struct page* pg;
  uint64_t nframe;
  
  pfa_assert_lock();
  
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
  pfa_stat_add(n_pfa_fault, 1, current);

  /* Note: we must already hold mm->mmap_sem or we could deadlock with kpfad */
  pfa_lock();

  if(!pfa_get_tsk()) {
    pfa_trace("Page fault on remote page after PFA exited\n");
    return VM_FAULT_SIGBUS;
  }

  /* It's OK to call these even if their queues don't need processing */
  pfa_fill_freeq();
  pfa_drain_newq();
 
  pfa_unlock();

  return 0;
}

void pfa_frameq_push(struct page *frame)
{
  pfa_assert_lock();
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

  pfa_assert_lock();
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
  
  /* pfa_assert_lock(); */
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
    panic("Calling pfa_set_tsk after it's already set (call pfa_clear_tsk first!)\n");
  }
  pfa_trace("Setting (pid=%d) as pfa_task\n", task_tgid_vnr(tsk));
  pfa_tsk = tsk;

  kpfad_tsk = kthread_run(kpfad, NULL, "kpfad");
  
  return;
}

void pfa_clear_tsk(void)
{
  pfa_trace("De-registering pfa task\n");

  /* Can't hold pfa_lock because kthread_stop blocks until kpfad_tsk exits. */
  kthread_stop(kpfad_tsk);

  pfa_lock();

  pfa_drain_newq();
  pfa_tsk = NULL;

  /* XXX PFA I'm not sure this is needed */
  flush_tlb_all();

  pfa_unlock();

  /* In practice, I should also free the frames in pfa_frameq */
  return;
}

/* PFA management daemon. Mostly drains newq and fills freeq. */
static int kpfad(void *p)
{
  while(1) {
    uint64_t start = pfa_stat_clock();
    pfa_trace("kpfad running\n");

    if (kthread_should_stop())
      break;

    /* NOTE: Lock acquisition order matters here */
    down_read(&pfa_tsk->mm->mmap_sem);
    /* Not a big deal if we can't get the pfa_lock, just try again later */
    if(pfa_trylock()) {
      BUG_ON(!pfa_get_tsk());
      pfa_fill_freeq();
      pfa_drain_newq();
      pfa_unlock();
    }
    up_read(&pfa_tsk->mm->mmap_sem);

    pfa_stat_add(t_kpfad, pfa_stat_clock() - start, pfa_get_tsk());
    usleep_range(5000, 15000);
  }

  pfa_trace("kpfad exiting\n");
  return 0;
}

ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  if(pfa_tsk) {
    return sprintf(buf, "%d\n", task_tgid_vnr(pfa_tsk));
  } else {
    return sprintf(buf, "-1\n");
  }
}

static ssize_t pfa_sysfs_store_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count)
{
  pid_t pid;
  struct task_struct *tsk = NULL;
  if(kstrtoint(buf, 10, &pid) == 0) {
    tsk = find_task_by_vpid(pid);
  }

  if(tsk) {
    pfa_set_tsk(tsk);
  } else {
    pfa_trace("Invalid pfa_tsk pid provided\n");
  }

  return count;
}

