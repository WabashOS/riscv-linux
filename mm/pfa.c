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

#ifdef CONFIG_PFA

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

DEFINE_MUTEX(pfa_mutex_global);
DEFINE_MUTEX(pfa_mutex_evict);

/* sysfs stuff */
ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute pfa_sysfs_tsk = __ATTR(pfa_tsk, 0660, pfa_sysfs_show_tsk, pfa_sysfs_store_tsk);

/* Global var. See pfa.h for details */
struct task_struct *pfa_tsk[PFA_MAX_TASKS];

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
#define PFA_FRAMEQ_MAX (CONFIG_PFA_FREEQ_SIZE + CONFIG_PFA_NEWQ_SIZE)
int pfa_frameq_head = 0;
int pfa_frameq_tail = 0;
int pfa_frameq_size = 0;
struct page* pfa_frameq[PFA_FRAMEQ_MAX] = {NULL};

/* kpfad settings */
struct task_struct *kpfad_tsk = NULL;
size_t kpfad_sleeptime = 10000; /* how long to sleep (in us)*/
/* Max and min time between kpfad run times (in us) */
/* 1s */
#define KPFAD_SLEEP_MAX 100000000
/* 5ms */
#define KPFAD_SLEEP_MIN 5000

/* How flexible (in us) to be in re-scheduling */
#define KPFAD_SLEEP_SLACK 10000

/* Every time kpfad runs it decs sleeptime by SLEEP_DEC.
 * Every time the pfa has to cause a fault (to get service) we increment by SLEEP_INC
 * This attempts to adapt kpfad overhead to usage */
/* XXX PFA should I do percents instead? */
#define KPFAD_SLEEP_DEC 1000
#define KPFAD_SLEEP_INC 100

static inline void kpfad_inc_sleep(void)
{
  kpfad_sleeptime += KPFAD_SLEEP_INC;
    if(kpfad_sleeptime > KPFAD_SLEEP_MAX)
      kpfad_sleeptime = KPFAD_SLEEP_MAX;
}

static inline void kpfad_dec_sleep(void)
{
  kpfad_sleeptime -= KPFAD_SLEEP_DEC;
    if(kpfad_sleeptime < KPFAD_SLEEP_MIN)
      kpfad_sleeptime = KPFAD_SLEEP_MIN;
}

/* Local Functions */
/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
static void pfa_free(struct page *pg);

/* Will busy wait until the PFA is done evicting everythign in its evict queue */
static void pfa_evict_poll(void);

#ifdef CONFIG_PFA_KPFAD
/* PFA management daemon. Mostly drains newq and fills freeq. */
static int kpfad(void *p);
#endif

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

static void pfa_evict_poll(void)
{
  /* Wait for completion */
  mb();
  while(readq(pfa_io_evictstat) < CONFIG_PFA_EVICTQ_SIZE) { cpu_relax(); }
  mb();
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(swp_entry_t swp_ent, uintptr_t page_paddr, uintptr_t vaddr,
    struct task_struct *tsk)
{
  uint64_t evict_val;
  uint64_t start;

  /* Evict Page */
  pfa_trace("Evicting page (vaddr=0x%lx) (paddr=0x%lx) (pgid=0x%x) (tsk=%d)\n",
      vaddr,
      page_paddr,
      pfa_swp_to_pgid(swp_ent, current->pfa_tsk_id),
      tsk->pfa_tsk_id);

#ifdef CONFIG_PFA_DEBUG
  /* I'm not sure if this is possible in Linux, but free frames may end up on
   * the lru lists and get re-selected for eviction. */
  if(pfa_frameq_search(page_paddr)) {
      panic("Evicting frame on frameq: (paddr=0x%lx)\n", page_paddr);
  }

  /* The PFA will get right-screwy if we evict shared pages. Who knows what
   * chaos might ensue if that happens! */
  int mapcount = page_mapcount(phys_to_page(page_paddr));
  if(mapcount > 1) {
    panic("Page (paddr=0x%lx) shared %d times (sharing not supported in pfa)\n",
        page_paddr, mapcount);
  }
#endif

  /* Form the packed eviction value defined in pfa spec */
  evict_val = page_paddr >> PAGE_SHIFT;
  PFA_ASSERT(evict_val >> PFA_EVICT_PGID_SHIFT == 0, "paddr component of eviction string too large\n");
  evict_val |= ((uint64_t)pfa_swp_to_pgid(swp_ent, tsk->pfa_tsk_id) << PFA_EVICT_PGID_SHIFT);

  start = pfa_stat_clock();
  
  pfa_lock(evict);
  writeq(evict_val, pfa_io_evict);
  pfa_evict_poll();
 
  pfa_unlock(evict);

  pfa_stat_add(t_rmem_write, pfa_stat_clock() - start);
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
 * mmap_sem_tskid: You may optionally hold the mmap_sem on exactly one task.
 *    this holds it's task_id (-1 if caller doesn't hold any mmap_sems).
 *
 * Note: Much of this code is stolen from handle_mm_fault */
static void pfa_new(int mmap_sem_tsk)
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
  struct task_struct *tsk;

  pgd_t *pgd;
  p4d_t *p4d;

#ifdef CONFIG_PFA_DEBUG
  PFA_ASSERT(readq(pfa_io_newstat) != 0, "Trying to pop empty newq\n");
#endif

  /* Get the new page info from newq and frameq */
  vmf.address = readq(pfa_io_newvaddr) & PAGE_MASK;
  new_pgid = (pfa_pgid_t)readq(pfa_io_newpgid);
  
  entry = pfa_pgid_to_swp(new_pgid);
  
  tsk = pfa_get_tsk(pfa_pgid_to_tsk(new_pgid));
  PFA_ASSERT(tsk != NULL, "Couldn't find taskID %d\n", pfa_pgid_to_tsk(new_pgid));

  mm = tsk->mm;
  PFA_ASSERT(mm, "Task has no struct mm!\n");

  if(tsk->pfa_tsk_id != mmap_sem_tsk) {
    down_read(&(tsk->mm->mmap_sem));
  }
  
  vmf.vma = find_vma(mm, vmf.address);
  PFA_ASSERT(vmf.vma, "Bad VMA\n");
  /* The actual check in do_page_fault is more complicated than this
   * I'm assuming swap-triggered page faults always satisfy this */
  PFA_ASSERT((vmf.vma->vm_start <= vmf.address), "Address out of bounds\n");

  /* XXX gfp_mask gets set in normal swap path but seems unused. */
  vmf.flags = flags;
  vmf.pgoff = linear_page_index(vmf.vma, vmf.address);

  /* Page-table walk to get pte. 
   * Much error-checking elided. Look at __handle_mm_fault and
   * _handle_pte_fault for more realistic error checking. */
	pgd = pgd_offset(mm, vmf.address);
  PFA_ASSERT(pgd, "Bad PGD\n");
	p4d = p4d_alloc(mm, pgd, vmf.address);
  PFA_ASSERT(p4d, "Bad P4D\n");
	vmf.pud = pud_alloc(mm, p4d, vmf.address);
  PFA_ASSERT(vmf.pud, "Bad PUD\n");
	vmf.pmd = pmd_alloc(mm, vmf.pud, vmf.address);
  PFA_ASSERT(vmf.pmd, "Bad PMD\n");
  vmf.pte = pte_offset_map(vmf.pmd, vmf.address);
  PFA_ASSERT(vmf.pte, "Bad PTE\n");
  
  vmf.orig_pte = *vmf.pte;
  PFA_ASSERT(!pte_none(vmf.orig_pte), "Invalid PTE\n");

  pfa_trace("Fetching New Page: (pgid=0x%x) (vaddr=0x%lx) (tsk=%d) (pte=0x%lx)\n",
      new_pgid,
      vmf.address,
      pfa_pgid_to_tsk(new_pgid),
      pte_val(vmf.orig_pte));

  /* Put the swap entry back into the PTE so we can use the unmodified
   * do_swap_page 
   * NOTE: this clears _PAGE_FETCHED as well */
  vmf.orig_pte = swp_entry_to_pte(entry);
	set_pte_at(mm, vmf.address, vmf.pte, vmf.orig_pte);

  ret = do_swap_page(&vmf);
  PFA_ASSERT(!(ret & VM_FAULT_ERROR), "Failed to bookkeep page in do_swap_page()\n");

  if(tsk->pfa_tsk_id != mmap_sem_tsk)
    up_read(&(tsk->mm->mmap_sem));

  return;
}

void pfa_drain_newq(int mmap_sem_tsk)
{
  uint64_t nnew;
  uint64_t cycles = pfa_stat_clock();

  pfa_assert_lock(global);

  nnew = readq(pfa_io_newstat);
  pfa_stat_add(n_fetched, nnew);
  if(nnew) 
    pfa_trace("Draining %lld items from newq\n", nnew);

  while(nnew)
  {
    pfa_new(mmap_sem_tsk); 
    nnew--;
  }

  pfa_stat_add(t_bookkeeping, pfa_stat_clock() - cycles);
}

void pfa_fill_freeq(void)
{
  struct page* pg;
  uint64_t nframe;
  
  pfa_assert_lock(global);
  
  nframe = readq(pfa_io_freestat);

  while(nframe) {
    /* This might block or trigger swapping which would be bad if we call
     * pfa_fill_new from the pageout path... */
    pg = alloc_page(GFP_HIGHUSER_MOVABLE);

#ifdef CONFIG_PFA_DEBUG
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

int pfa_handle_fault(struct vm_fault *vmf)
{
  pfa_trace("Page fault received on remote page (vaddr=0x%lx) (tsk=%d)\n",
      vmf->address & PAGE_MASK,
      current->pfa_tsk_id);
  pfa_stat_add(n_pfa_fault, 1);

  /* Note: we must already hold mm->mmap_sem or we could deadlock with kpfad */
  pfa_lock(global);

  if(!is_pfa_tsk(current)) {
    pfa_trace("Page fault on remote page after PFA exited\n");
    return VM_FAULT_SIGBUS;
  }

  /* It's OK to call these even if their queues don't need processing */
  pfa_fill_freeq();
  pfa_drain_newq(current->pfa_tsk_id);

#ifdef CONFIG_PFA_KPFAD
  kpfad_dec_sleeptime();
#endif

  pfa_unlock(global);

  /* Even though we didn't change the PTE, we must flush pte from the TLB
   * to trigger another PT walk (at least on Rocket) */
	update_mmu_cache(vmf->vma, vmf->address, vmf->pte);

  return 0;
}

void pfa_frameq_push(struct page *frame)
{
  pfa_assert_lock(global);
  PFA_ASSERT(pfa_frameq_size != PFA_FRAMEQ_MAX, "Pushing to full frameq\n");

#ifdef CONFIG_PFA_DEBUG
  PFA_ASSERT(!pfa_frameq_search(page_to_phys(frame)), "Frame already on frameq\n");
#endif

  pfa_frameq[pfa_frameq_head] = frame;

  pfa_frameq_head = (pfa_frameq_head + 1) % PFA_FRAMEQ_MAX;
  pfa_frameq_size++;

  return;
}

struct page* pfa_frameq_pop(void)
{
  struct page *ret;

  pfa_assert_lock(global);
  PFA_ASSERT(pfa_frameq_size != 0, "Popping from empty frameq\n");
  
  ret = pfa_frameq[pfa_frameq_tail];
  PFA_ASSERT(ret != NULL, "FrameQ Corrupted\n");
  
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

int pfa_set_tsk(struct task_struct *tsk)
{
  int tsk_idx = 0;

  /* Find the next from slot in task list */
  for(tsk_idx = 0; tsk_idx < PFA_MAX_TASKS; tsk_idx++) {
    if(pfa_tsk[tsk_idx] == NULL)
      break;
  }
  if(tsk_idx == PFA_MAX_TASKS) {
    pfa_warn("Ran out of pfa task slots (only 32 allowed)!\n");
    return 0;
  }

  pfa_trace("Setting (pid=%d) as a pfa_task (tsk=%d)\n", task_tgid_vnr(tsk),
      tsk_idx);

  /* XXX PFA This code is written to eventually support multiple tasks. However,
   * this might not fully work yet. Right now we enforce only 1 task at a time.*/
  /* if(tsk_idx != 0) { */
  /*   panic("PFA doesn't support more than one task right now\n"); */
  /* } */
  pfa_tsk[tsk_idx] = tsk;
  tsk->pfa_tsk_id = tsk_idx;

#ifdef CONFIG_PFA_KPFAD
  kpfad_tsk = kthread_run(kpfad, NULL, "kpfad");
#endif
  return 1;
}

void pfa_clear_tsk(int tsk_id)
{
  PFA_ASSERT(tsk_id < PFA_MAX_TASKS && tsk_id >= 0, "Invalid task id: %d\n", tsk_id);
  PFA_ASSERT(pfa_tsk[tsk_id] != NULL, "No valid PFA task at tskid %d\n", tsk_id);
  pfa_trace("De-registering pfa task (tsk=%d)\n", tsk_id);

#ifdef CONFIG_PFA_KPFAD
  /* Can't hold pfa_lock because kthread_stop blocks until kpfad_tsk exits. */
  kthread_stop(kpfad_tsk);
#endif

  pfa_lock(global);

  pfa_drain_newq(-1);
  pfa_tsk[tsk_id]->pfa_tsk_id = -1;
  pfa_tsk[tsk_id] = NULL;

  pfa_unlock(global);

  /* In practice, I should also free the frames in pfa_frameq */
  return;
}

#ifdef CONFIG_PFA_KPFAD
/* PFA management daemon. Mostly drains newq and fills freeq. */
static int kpfad(void *p)
{
  /* XXX Need to play around to see if this is a good idea... */
	/* set_user_nice(current, MIN_NICE); */

  while(1) {
    uint64_t start = pfa_stat_clock();
    pfa_stat_add(n_kpfad, 1);
    pfa_trace("kpfad running\n");

    if (kthread_should_stop())
      break;

    /* NOTE: Lock acquisition order matters here */
    /* Not a big deal if we can't get the pfa_lock, just try again later */
    if(pfa_trylock(global)) {
      pfa_fill_freeq();
      pfa_drain_newq(-1);

      /* Calculate next sleep time */
      kpfad_inc_sleep();
      
      pfa_unlock(global);
    }

    pfa_stat_add(t_kpfad, pfa_stat_clock() - start);

    usleep_range(kpfad_sleeptime, kpfad_sleeptime + KPFAD_SLEEP_SLACK);
  }

  pfa_trace("kpfad exiting\n");
  return 0;
}
#endif

ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  int i;
  int line_size = 0;
  int total_size = 0;
  struct task_struct *tsk;

  for(i = 0; i < PFA_MAX_TASKS; i++) {
    tsk = pfa_get_tsk(i);
    if(tsk) {
       line_size = sprintf(buf, "%d\n", task_tgid_vnr(tsk));
       buf += line_size;
       total_size += line_size;
    }
  }

  return total_size;
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

#else //ifdef CONFIG_PFA

/* This is the minimum needed to not use the PFA (baseline experiments)
 * Mostly this stuff is for stats collection */

/* sysfs stuff */
ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute pfa_sysfs_tsk = __ATTR(pfa_tsk, 0660, pfa_sysfs_show_tsk, pfa_sysfs_store_tsk);

/* Global var. See pfa.h for details */
struct task_struct *pfa_tsk[PFA_MAX_TASKS];

/* Assigns "tsk" to the PFA and gives it a pfa_tsk_id.
 * Returns 1 on success, 0 on failure (likely due to too many active pfa
 * tasks) */
int pfa_set_tsk(struct task_struct *tsk)
{
    int tsk_idx = 0;

    /* Find the next from slot in task list */
    for(tsk_idx = 0; tsk_idx < PFA_MAX_TASKS; tsk_idx++) {
      if(pfa_tsk[tsk_idx] == NULL)
        break;
    }
    if(tsk_idx == PFA_MAX_TASKS) {
      pfa_warn("Ran out of pfa task slots (only 32 allowed)!\n");
      return 0;
    }

    pfa_trace("Setting (pid=%d) as a pfa_task (tsk=%d)\n", task_tgid_vnr(tsk),
        tsk_idx);

    /* XXX PFA This code is written to eventually support multiple tasks. However,
     * this might not fully work yet. Right now we enforce only 1 task at a time.*/
    /* if(tsk_idx != 0) { */
    /*   panic("PFA doesn't support more than one task right now\n"); */
    /* } */
    pfa_tsk[tsk_idx] = tsk;
    tsk->pfa_tsk_id = tsk_idx;
    return 1;
}

/* Must down pfa_tsk->mm->mmap_sem before calling.
 * tsk_id: The struct task_struct->pfa_tsk_id feild*/
void pfa_clear_tsk(int tsk_id)
{
  pfa_tsk[tsk_id]->pfa_tsk_id = -1;
  pfa_tsk[tsk_id] = NULL;
  return;
}

ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  int i;
  int line_size = 0;
  int total_size = 0;
  struct task_struct *tsk;

  for(i = 0; i < PFA_MAX_TASKS; i++) {
    tsk = pfa_tsk[i];
    if(tsk) {
       line_size = sprintf(buf, "%d\n", task_tgid_vnr(tsk));
       buf += line_size;
       total_size += line_size;
    }
  }

  return total_size;
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

void pfa_init(void)
{
  /* Create sysfs interface
   * Don't fail on errors, User won't be able to use PFA, but we don't need
   * to crash the kernel either */
    if(sysfs_create_file(mm_kobj, &pfa_sysfs_tsk.attr) != 0)
          pr_err("Failed to create sysfs entries\n");
  
  return;
}
#endif
