#include <linux/mm.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kobject.h>
#include <linux/timex.h>
#include <linux/pfa.h>
#include <linux/pfa_stat.h>
#include <linux/icenet_raw.h>
#include <linux/memblade_client.h>
#include <asm/tlbflush.h>
#include "internal.h"

#if defined(CONFIG_PFA_VERBOSE) && defined(PFA_LOG_DEFER)
/* Deferred pfa logging */
DEFINE_SPINLOCK(pfa_log_mut);
uint8_t *pfa_log;
size_t pfa_log_end = 0;
#endif

/* Protects only direct access to HW queues 
 * Used by memblade as well (even when PFA not enabled)*/
DEFINE_SPINLOCK(pfa_hw_mut);

#ifdef CONFIG_PFA

/* Phyiscal addr for MMIO to pfa (see the PFA spec for details) */
#define PFA_IO_BASE                0x10017000 
#define PFA_IO_FREEFRAME           (PFA_IO_BASE)
#define PFA_IO_FREESTAT            (PFA_IO_BASE + 8)
#define PFA_IO_EVICTPAGE           (PFA_IO_BASE + 16)
#define PFA_IO_EVICTSTAT           (PFA_IO_BASE + 24)
#define PFA_IO_NEWPGID             (PFA_IO_BASE + 32)
#define PFA_IO_NEWVADDR            (PFA_IO_BASE + 40)
#define PFA_IO_NEWSTAT             (PFA_IO_BASE + 48)
#define PFA_IO_DSTMAC              (PFA_IO_BASE + 56)

DECLARE_RWSEM(pfa_mutex_global);
spinlock_t pfa_evict_mut;

/* sysfs stuff */
ssize_t pfa_sysfs_show_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_tsk(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute pfa_sysfs_tsk = __ATTR(pfa_tsk, 0660, pfa_sysfs_show_tsk, pfa_sysfs_store_tsk);

/* Global var. See pfa.h for details */
struct task_struct *pfa_tsk[PFA_MAX_TASKS];

#ifdef CONFIG_PFA_EM

/* This mutex enforces atomic reads/writes from/to the emulated PFA queues. */
DEFINE_SPINLOCK(pfa_em_mut);

DEFINE_PQ(pfa_freeq, CONFIG_PFA_FREEQ_SIZE, uintptr_t);
DECLARE_PQ(pfa_freeq, CONFIG_PFA_FREEQ_SIZE);

DEFINE_PQ(pfa_new_id, CONFIG_PFA_NEWQ_SIZE, pfa_pgid_t);
DECLARE_PQ(pfa_new_id, CONFIG_PFA_NEWQ_SIZE);
DEFINE_PQ(pfa_new_vaddr, CONFIG_PFA_NEWQ_SIZE, uintptr_t);
DECLARE_PQ(pfa_new_vaddr, CONFIG_PFA_NEWQ_SIZE);

#else
/* After initialization, points to the kernel MMIO addresses for the PFA */
void __iomem *pfa_io_free;
void __iomem *pfa_io_freestat;
void __iomem *pfa_io_evict;
void __iomem *pfa_io_evictstat;
void __iomem *pfa_io_newpgid;
void __iomem *pfa_io_newvaddr;
void __iomem *pfa_io_newstat;
void __iomem *pfa_io_dstmac;
#endif

/* Holds every frame (struct page*) that is given to the PFA in FIFO order
 * It's possible with kpfad to fill the freeq twice before processing new pages:
 * 1. read newq_stat, see no new entries, don't empty
 * 2. before reading freeq_stat, NEWQ_SIZE faults occur filling newq with unproccessed faults
 * 3. observe NEWQ_SIZE empty slots from freeq_stat and fill them in
 */
#define PFA_FRAMEQ_MAX (CONFIG_PFA_FREEQ_SIZE + CONFIG_PFA_NEWQ_SIZE)
DEFINE_PQ(pfa_frameq, PFA_FRAMEQ_MAX, struct page*);
DECLARE_PQ(pfa_frameq, PFA_FRAMEQ_MAX);

/* kpfad settings */
struct task_struct *kpfad_tsk = NULL;
size_t kpfad_sleeptime = 1000; /* how long to sleep (in us)*/
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

/* #ifdef CONFIG_PFA_DEBUG */
#if defined(CONFIG_PFA_DEBUG) && defined(CONFIG_PFA_EM)

DEFINE_HASHTABLE(pfa_dbg_page, 12);
dbg_page_t *pfa_dbg_page_freeent;
uint8_t *pfa_dbg_page_freepg;
HLIST_HEAD(pfa_dbg_page_free);
DEFINE_SPINLOCK(pfa_dbg_page_lock);

void pfa_dbg_record_page(void *pg, uintptr_t vaddr, void *priv)
{
  unsigned long flags;
  dbg_page_t *ent;
  spin_lock_irqsave(&pfa_dbg_page_lock, flags);
  PFA_ASSERT(!hlist_empty(&pfa_dbg_page_free), "debug page list full\n");
  ent = hlist_entry(pfa_dbg_page_free.first, dbg_page_t, _hash);
  hlist_del(&(ent->_hash));

  memcpy(ent->pg, pg, PAGE_SIZE);
  ent->vaddr = vaddr;
  ent->priv = priv;

  hash_add(pfa_dbg_page, &(ent->_hash), ent->vaddr);
  spin_unlock_irqrestore(&pfa_dbg_page_lock, flags);
}

dbg_page_t *pfa_dbg_get_page(uintptr_t vaddr)
{
  unsigned long flags;
  dbg_page_t *ent;

  spin_lock_irqsave(&pfa_dbg_page_lock, flags);
  hash_for_each_possible(pfa_dbg_page, ent, _hash, vaddr) {
    if(ent->vaddr == vaddr) {
      spin_unlock_irqrestore(&pfa_dbg_page_lock, flags);
      return ent;
    }
  }
  spin_unlock_irqrestore(&pfa_dbg_page_lock, flags);
  return NULL;
}

void pfa_dbg_free_page(dbg_page_t *ent)
{
  unsigned long flags;
  spin_lock_irqsave(&pfa_dbg_page_lock, flags);
  hash_del(&(ent->_hash));
  hlist_add_head(&(ent->_hash), &(pfa_dbg_page_free));
  spin_unlock_irqrestore(&pfa_dbg_page_lock, flags);
}

#endif //defined CONFIG_PFA_DEBUG && CONFIG_PFA_EM

/* PTE tracking for evicted pages 
 * We need to modify PTEs after pages have been written back to RMEM when using
 * the PFA. Unfortunately, Linux removes the mappings well before actually
 * writing the pages back. To get around this, we track the PTEs that reference
 * a page in the pfa_epgs list below during this window.
 *
 * Note: There are a number of hacks here that are technically wrong:
 *    1. Currently assumes one ptep per evicted page, but for shared pages, there could be more. We should really make ptep a linked-list.
 *    2. ptep stores a pointer to the PTE, this could technically change under
 *    our feet. The "right" way would be to repeat the PT walk, which would be
 *    slow and ugly.
 */
#define PFA_EPG_SZ 10
typedef struct pfa_epg {
  struct page *pg;
  struct vm_area_struct *vma;
  unsigned long addr;
  pmd_t *pmd;
  pte_t *ptep;
  pte_t rem_pteval;
} pfa_epg_t;

/* List of pending evicted pages that haven't been made official yet
 * Note: there is at most one per concurrent eviction. This seems to be
 * 1/process but it's possible with kswapd that multiple could be
 * outstanding. */
pfa_epg_t pfa_epgs[PFA_EPG_SZ] = {{0}};

// Number of pages in the evicted page queue
int pfa_epg_cnt = 0;

/* Applies the new remote pte value to the PTEs associated with the evicted page.
 * Invalidates PTEs immediately (really this should be batched or something...) */
void pfa_epg_apply(struct page *pg)
{
  unsigned long flags;
  pfa_epg_t *ent;
  struct vm_area_struct *vma;
  unsigned long addr;
  int i;

  spin_lock_irqsave(&pfa_evict_mut, flags);
  for(i = 0; i < PFA_EPG_SZ; i++) {
    ent = &pfa_epgs[i];
    if(ent->pg == pg) {
      pfa_trace("Re-writing pte for: (ptep=0x%p vaddr=0x%lx from=0x%lx to=0x%lx)\n",
          ent->ptep, ent->addr, (*ent->ptep).pte, ent->rem_pteval.pte);

      /* epg is applied only after the page has been completely unmapped.
       * handle_pte_fault should be the only place that the PTE is touched
       * again and it removes the epg entry if we get a fault on it before
       * fully applying the epg, this should be sufficient to prevent a race
       * (so we shouldn't need the ptl here). Note also, grabbing the ptl here
       * can hang for unknown reasons. */
      set_pte(ent->ptep, ent->rem_pteval);

      vma = ent->vma;
      addr = ent->addr;
      *ent = (const pfa_epg_t){0};
      pfa_epg_cnt--;
      PFA_ASSERT(pfa_epg_cnt >= 0, "Popping from empty list\n");

      //XXX PFA
      /* flush_tlb_page(vma, addr); */
      flush_tlb_all();
      spin_unlock_irqrestore(&pfa_evict_mut, flags);
      return;
    }
  }
  // Silently ignore requests for pages not in the epg
  spin_unlock_irqrestore(&pfa_evict_mut, flags);
  return;
}

/* Place a page into the evicted pages list */
void pfa_epg_add(struct page *pg, pmd_t *pmd, pte_t *ptep, pte_t rem_pteval, struct
    vm_area_struct *vma, unsigned long addr)
{
  unsigned long flags;
  int i;

  spin_lock_irqsave(&pfa_evict_mut, flags);
  for(i = 0; i < PFA_EPG_SZ; i++) {
    if(pfa_epgs[i].pg == NULL) {
      pfa_epgs[i].pg = pg;
      pfa_epgs[i].ptep = ptep;
      pfa_epgs[i].rem_pteval = rem_pteval;
      pfa_epgs[i].vma = vma;
      pfa_epgs[i].addr = addr;
      pfa_epg_cnt++;
      spin_unlock_irqrestore(&pfa_evict_mut, flags);
      return;
    }
  }
  spin_unlock_irqrestore(&pfa_evict_mut, flags);
  PFA_ASSERT(0, "Evicted page list full!\n");
}

int pfa_epg_drop(struct page *pg)
{
  unsigned long flags;
  int i;

  spin_lock_irqsave(&pfa_evict_mut, flags);
  for(i = 0; i < PFA_EPG_SZ; i++) {
    if(pfa_epgs[i].pg == pg) {
      pfa_trace("Aborting eviction by page (vaddr=0x%lx)\n",
          pfa_epgs[i].addr);
      pfa_epgs[i] = (const pfa_epg_t){0};
      pfa_epg_cnt--;
      PFA_ASSERT(pfa_epg_cnt >= 0, "Popping from empty list\n");
      spin_unlock_irqrestore(&pfa_evict_mut, flags);
      return 1;
    }
  }
  // Silently ignore requests for pages not in the epg
  spin_unlock_irqrestore(&pfa_evict_mut, flags);
  return 0;
}

int pfa_epg_drop_ptep(pte_t *ptep) {
  unsigned long flags;
  int i;

  if(ptep == NULL) {
    return 0;
  }

  spin_lock_irqsave(&pfa_evict_mut, flags);
  for(i = 0; i < PFA_EPG_SZ; i++) {
    if(pfa_epgs[i].ptep == ptep) {
      pfa_trace("Aborting eviction by ptep (vaddr=0x%lx)\n",
          pfa_epgs[i].addr);
      pfa_epgs[i] = (const pfa_epg_t){0};
      pfa_epg_cnt--;
      PFA_ASSERT(pfa_epg_cnt >= 0, "Popping from empty list\n");
      spin_unlock_irqrestore(&pfa_evict_mut, flags);
      return 1;
    }
  }
  // Silently ignore requests for pages not in the epg
  spin_unlock_irqrestore(&pfa_evict_mut, flags);
  return 0;
}

int pfa_epg_get_cnt(void) {
  return pfa_epg_cnt;
}

static inline void kpfad_inc_sleep(void)
{
  return;
  /* kpfad_sleeptime += KPFAD_SLEEP_INC; */
  /*   if(kpfad_sleeptime > KPFAD_SLEEP_MAX) */
  /*     kpfad_sleeptime = KPFAD_SLEEP_MAX; */
}

static inline void kpfad_dec_sleep(void)
{
  return;
  /* kpfad_sleeptime -= KPFAD_SLEEP_DEC; */
  /*   if(kpfad_sleeptime < KPFAD_SLEEP_MIN) */
  /*     kpfad_sleeptime = KPFAD_SLEEP_MIN; */
}

/* Local Functions */
#ifdef CONFIG_PFA_EM
static void pfa_write_freeq(uintptr_t frame_paddr)
{
  unsigned long flags;
  spin_lock_irqsave(&pfa_em_mut, flags);
  PQ_PUSH(pfa_freeq, frame_paddr);
  spin_unlock_irqrestore(&pfa_em_mut, flags);
}

static uint64_t pfa_read_freestat(void)
{
  uint64_t res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_em_mut, flags);
  res = CONFIG_PFA_FREEQ_SIZE - PQ_CNT(pfa_freeq);
  spin_unlock_irqrestore(&pfa_em_mut, flags);
  return res;
}

static void pfa_write_evictq(uint64_t ev)
{
  uintptr_t page_paddr = (ev & ((1l << PFA_EVICT_RPN_SHIFT) - 1)) << PAGE_SHIFT;
  uint32_t rpn = (uint32_t)(ev >> PFA_EVICT_RPN_SHIFT);
  unsigned long flags;
  spin_lock_irqsave(&pfa_em_mut, flags);

  mb_send(page_paddr, (uintptr_t)NULL, MB_OC_PAGE_WRITE, rpn);
  mb_wait();

  spin_unlock_irqrestore(&pfa_em_mut, flags);
  return;
}

static int64_t pfa_read_evictstat(void)
{
  return CONFIG_PFA_EVICTQ_SIZE;
}

static pfa_pgid_t pfa_read_newpgid(void)
{
  uintptr_t vaddr;
  unsigned long flags;
  spin_lock_irqsave(&pfa_em_mut, flags);
  PQ_POP(pfa_new_id, vaddr);
  spin_unlock_irqrestore(&pfa_em_mut, flags);
  return vaddr;
}
 
static pfa_pgid_t pfa_read_newvaddr(void)
{
  pfa_pgid_t id;
  unsigned long flags;
  spin_lock_irqsave(&pfa_em_mut, flags);
  PQ_POP(pfa_new_vaddr, id);
  spin_unlock_irqrestore(&pfa_em_mut, flags);
  return id;
}
 
static int64_t pfa_read_newstat(void)
{
  int64_t res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_em_mut, flags);
  /* The real HW checks only new_id here. Honestly, this should be the max(id,
   * vaddr), but SW never checks this when the queues are out of sync. */
  res = PQ_CNT(pfa_new_id);
  spin_unlock_irqrestore(&pfa_em_mut, flags);
  return res;
}

static void pfa_write_dstmac(uint64_t dstmac)
{
  return;
}

#else //CONFIG_PFA_EM

static void pfa_write_freeq(uintptr_t frame_paddr)
{
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);
  writeq(frame_paddr, pfa_io_free);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
}

static uint64_t pfa_read_freestat(void)
{
  uint64_t res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);
  res = readq(pfa_io_freestat);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
  return res;
}

static void pfa_write_evictq(uint64_t ev)
{
  /* unsigned long flags; */
  /* spin_lock_irqsave(&pfa_hw_mut, flags); */
  writeq(ev, pfa_io_evict);
  /* spin_unlock_irqrestore(&pfa_hw_mut, flags); */
}

static uint64_t pfa_read_evictstat(void)
{
  uint64_t res;
  /* unsigned long flags; */
  /* spin_lock_irqsave(&pfa_hw_mut, flags); */
  res = readq(pfa_io_evictstat);
  /* spin_unlock_irqrestore(&pfa_hw_mut, flags); */
  return res;
}

static pfa_pgid_t pfa_read_newpgid(void)
{
  pfa_pgid_t res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);
  res = (pfa_pgid_t)readq(pfa_io_newpgid);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
  return res;
}
 
static uintptr_t pfa_read_newvaddr(void)
{
  uintptr_t res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);
  res = readq(pfa_io_newvaddr);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
  return res;
}
  
static uint64_t pfa_read_newstat(void)
{
  uint64_t res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);
  res = readq(pfa_io_newstat);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
  return res;
}

static void pfa_write_dstmac(uint64_t dstmac)
{
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);
  writeq(dstmac, pfa_io_dstmac);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
}
#endif

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

void pfa_init(uint64_t memblade_mac)
{
  printk("Linux Initializing PFA\n");
  spin_lock_init(&pfa_evict_mut);

#if defined(CONFIG_PFA_VERBOSE) && defined(PFA_LOG_DEFER)
  pfa_log = vzalloc(PFA_LOG_SZ);
  if(!pfa_log) {
    panic("Failed to allocate pfa log\n");
  }
#endif

  /* Create sysfs interface
   * Don't fail on errors, User won't be able to use PFA, but we don't need
   * to crash the kernel either */
    if(sysfs_create_file(mm_kobj, &pfa_sysfs_tsk.attr) != 0)
          pr_err("Failed to create sysfs entries\n");
  
#ifndef CONFIG_PFA_EM
  /* Setup MMIO */
  pfa_io_free = ioremap(PFA_IO_FREEFRAME, 8);
  pfa_io_freestat = ioremap(PFA_IO_FREESTAT, 8);
  pfa_io_evict = ioremap(PFA_IO_EVICTPAGE, 8);
  pfa_io_evictstat = ioremap(PFA_IO_EVICTSTAT, 8);
  pfa_io_newpgid = ioremap(PFA_IO_NEWPGID, 8);
  pfa_io_newvaddr = ioremap(PFA_IO_NEWVADDR, 8);
  pfa_io_newstat = ioremap(PFA_IO_NEWSTAT, 8);
  pfa_io_dstmac = ioremap(PFA_IO_DSTMAC, 8);
#endif

  /* PFA currently only supports one memoryblade, statically configured */
  printk("memblade mac: 0x%llx\n", memblade_mac);
  /* pfa_write_dstmac(CONFIG_MEMBLADE_MAC); */
  pfa_write_dstmac(memblade_mac);

  return;
}

static void pfa_evict_poll(void)
{
  /* Wait for completion */
  mb();
  while(pfa_read_evictstat() < CONFIG_PFA_EVICTQ_SIZE) { cpu_relax(); }
  mb();
  return;
}

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 *
 * We hold the page lock for page_paddr.
 * We do NOT hold the pfa_global lock here. Be careful!
 */
void pfa_evict(uintptr_t rpn, phys_addr_t page_paddr)
{
  uint64_t evict_val;
  unsigned long flags;

  pfa_trace("Actual eviction: (rpn=0x%lx) (paddr=0x%llx)\n", rpn, page_paddr);
  /* Form the packed eviction value defined in pfa spec */
  evict_val = page_paddr >> PAGE_SHIFT;
  PFA_ASSERT(evict_val >> PFA_EVICT_RPN_SHIFT == 0, "paddr component of eviction string too large\n");
  evict_val |= rpn << PFA_EVICT_RPN_SHIFT;

  
  /* Eviction must be atomic with respect to other PFA accesses. Interleaved
   * accesses could hang or trigger bogus page-faults.*/
  spin_lock_irqsave(&pfa_hw_mut, flags);
  pfa_write_evictq(evict_val);
  pfa_evict_poll();
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
}

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
static void pfa_free(struct page* pg)
{
  pfa_trace("Adding (paddr=0x%lx) to freelist\n", (unsigned long)page_to_phys(pg));
  pfa_write_freeq(page_to_phys(pg));
  pfa_frameq_push(pg);
}

/* Process one entry from the newq.
 * Assumes there is at least one entry in newq (check NEWSTAT first). 
 * mmap_sem_tskid: You may optionally hold the mmap_sem on exactly one task.
 *    this holds it's task_id (-1 if caller doesn't hold any mmap_sems).
 *
 * Note: Much of this code is stolen from handle_mm_fault */
static void pfa_new(int mmap_sem_tsk, uintptr_t new_addr, pfa_pgid_t new_pgid)
{
  int ret;
  int pre;
  struct mm_struct *mm;
  /* These flags are coppied from do_page_fault, I'm not 100% on them */
  unsigned int flags = FAULT_FLAG_ALLOW_RETRY | 
                       FAULT_FLAG_KILLABLE |
                       FAULT_FLAG_USER;
	struct vm_fault vmf;
  swp_entry_t entry;
  int tskid;
  struct task_struct *tsk;

  pgd_t *pgd;
  p4d_t *p4d;
  
  uint64_t start = pfa_stat_clock();

  vmf.address = new_addr;
  
  entry = pfa_pgid_to_swp(new_pgid);
  
  tskid = pfa_pgid_to_tsk(new_pgid);
  tsk = pfa_get_tsk(tskid);
  PFA_ASSERT(tsk != NULL, "Couldn't find taskID %d\n", tskid);
  pfa_stat_add(n_fetched, 1, tsk);
  
  mm = tsk->mm;
  PFA_ASSERT(mm, "Task %d has no struct mm!\n", tskid);

  if(tsk->pfa_tsk_id != mmap_sem_tsk) {
    down_read(&(tsk->mm->mmap_sem));
  }
  
  vmf.vma = find_vma(mm, vmf.address);
  PFA_ASSERT(vmf.vma, "Bad VMA for tsk %d\n", tskid);
  /* The actual check in do_page_fault is more complicated than this
   * I'm assuming swap-triggered page faults always satisfy this */
  PFA_ASSERT((vmf.vma->vm_start <= vmf.address), "Address (0x%lx) out of bounds (tsk=%d)\n", vmf.address, tskid);

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

  pfa_trace("Fetching New Page: (ptep=0x%p) (pgid=0x%llx) (vaddr=0x%lx) (tsk=%d) (pte=0x%lx)\n",
      vmf.pte,
      new_pgid,
      vmf.address,
      tskid,
      pte_val(vmf.orig_pte));

  /* Put the swap entry back into the PTE so we can use the unmodified
   * do_swap_page 
   * NOTE: this clears _PAGE_FETCHED as well */
  /* XXX This loses the dirty bit (dealt with below). */
  vmf.orig_pte = swp_entry_to_pte(entry);
	set_pte_at(mm, vmf.address, vmf.pte, vmf.orig_pte);

  pre = PQ_CNT(pfa_frameq);
  vmf.flags |= FAULT_FLAG_PFA_NEW;
  //XXX PFA we treat every access as a "write" in order to preemptively dirty all
  //pages. This is not optimal (potentially many more evictions), but it avoids the chance
  //that a page was dirtied before we could bookkeep it
  vmf.flags |= FAULT_FLAG_WRITE;
  ret = do_swap_page(&vmf);
  PFA_ASSERT(PQ_CNT(pfa_frameq) == pre - 1, "do_swap_page didn't use a frame\n");
  PFA_ASSERT((ret == VM_FAULT_MAJOR) || (ret == (VM_FAULT_MAJOR | VM_FAULT_WRITE)),
      "Failed to bookkeep page in do_swap_page() (ret=0x%x, vaddr=0x%lx, tsk=%d)\n", ret, vmf.address, tskid);

  if(tsk->pfa_tsk_id != mmap_sem_tsk)
    up_read(&(tsk->mm->mmap_sem));

  pfa_stat_add(t_bookkeeping, pfa_stat_clock() - start, tsk);

  return;
}

#ifdef CONFIG_PFA_DEBUG
atomic64_t newq_unique = ATOMIC_INIT(0);
#endif

int pfa_drain_newq(int mmap_sem_tsk)
{
  uint64_t nnew;
  uintptr_t new_addr;
  pfa_pgid_t new_pgid;
  int i;

  pfa_assert_lock(global);
  PFA_ASSERT(atomic64_inc_return(&newq_unique) == 1, "attempted to enter drain_newq recursively\n");

  nnew = pfa_read_newstat();
  if(nnew) 
    pfa_trace("Draining %lld items from newq\n", nnew);

  for(i = 0; i < nnew; i++)
  {
#ifdef CONFIG_PFA_DEBUG
    PFA_ASSERT(pfa_read_newstat() != 0, "Trying to pop empty newq\n");
#endif

    new_addr = pfa_read_newvaddr() & PAGE_MASK;
    new_pgid = pfa_read_newpgid();
 
    pfa_new(mmap_sem_tsk, new_addr, new_pgid); 
  }

  PFA_ASSERT(atomic64_dec_return(&newq_unique) == 0, "drain newq was run concurrently\n");
  return nnew;
}

#ifdef CONFIG_PFA_DEBUG
atomic64_t freeq_unique = ATOMIC_INIT(0);
#endif

void pfa_fill_freeq(void)
{
  struct page* pg;
  uint64_t nframe;
  
  pfa_assert_lock(global);
  PFA_ASSERT(atomic64_inc_return(&freeq_unique) == 1, "attempted to enter drain_newq recursively\n");
  
  nframe = pfa_read_freestat();
  if(nframe > 0) {
    pfa_trace("Adding %llu frames to freelist\n", nframe);
  }

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
  PFA_ASSERT(atomic64_dec_return(&freeq_unique) == 0, "drain newq was run concurrently\n");
}

#ifdef CONFIG_PFA_EM
int pfa_em_checkQ(void) {
  uint64_t nfree, nnew_vaddr, nnew_pgid;

  nfree = PQ_CNT(pfa_freeq);
  nnew_vaddr  = PQ_CNT(pfa_new_vaddr);
  nnew_pgid  = PQ_CNT(pfa_new_id);
  if(nfree == 0 ||
     nnew_vaddr == CONFIG_PFA_NEWQ_SIZE ||
     nnew_pgid == CONFIG_PFA_NEWQ_SIZE)
  {
    pfa_trace("pfa_em: queue maintainence needed (freestat=%llu, nnewVaddr=%llu, nnewPgid=%llu)\n",
        CONFIG_PFA_FREEQ_SIZE - nfree, nnew_vaddr, nnew_pgid);
    return 0;
  }
  return 1;
} 

/* a very low-level walk. Returns NULL if it can't find the pte. */
pte_t *pfa_walk(struct mm_struct *mm, uintptr_t addr)
{
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;

  pgd = pgd_offset(mm, addr);
  if(!pgd || pgd_none(*pgd)) {
    return NULL;
  }

  p4d = p4d_offset(pgd, addr);
  if(!p4d || p4d_none(*p4d)) {
    return NULL;
  }

  pud = pud_offset(p4d, addr);
  if(!pud || pud_none(*pud)) {
    return NULL;
  }

  pmd = pmd_offset(pud, addr);
  if(!pmd || pmd_none(*pmd)) {
    return NULL;
  }

  return pte_offset_map(pmd, addr);
}

int pfa_em(struct mm_struct *mm, uintptr_t addr)
{
  uintptr_t dst_paddr;
  pfa_pgid_t pgid;
  uintptr_t rpn;
  pte_t lpte;
  unsigned long flags;
  pte_t *pte;
 
  /* Early (unsafe) check, we repeat the check with the lock held below */
  if(!pfa_em_checkQ()) {
    return -1;
  }

  /* If anything at all goes wrong, just bail out and let the normal handler
   * deal with it. A remote PTE would succeed. */
  pte = pfa_walk(mm, addr);
  if(!pte || pte_none(*pte)) {
    return -2;
  }
  
  if(pte_remote(*pte)) {
    // Bring in the new page
    // We access the queue directly because we hold the pfa_em_mut
    spin_lock_irqsave(&pfa_em_mut, flags);

    if(!pfa_em_checkQ()) {
      spin_unlock_irqrestore(&pfa_em_mut, flags);
      return -1;
    }

    PQ_POP(pfa_freeq, dst_paddr);
    pgid = pfa_remote_to_pgid(*pte);
    rpn = pfa_pgid_rpn(pgid);
    PFA_ASSERT(dst_paddr != 0, "NULL destination!");
    mb_send((uintptr_t)NULL, dst_paddr, MB_OC_PAGE_READ, rpn);
    mb_wait();
    
    // Update metadata
    // We use the queues directly because we hold pfa_em_mut
    PQ_PUSH(pfa_new_id, pgid);
    PQ_PUSH(pfa_new_vaddr, addr);

    // Create new local PTE
    lpte = pfa_remote_to_local(*pte, dst_paddr);

    pfa_trace("Placing rpn 0x%lx into paddr 0x%lx for vaddr 0x%lx (oldPTE=0x%lx, newPTE=0x%lx)\n",
        rpn,
        dst_paddr,
        addr,
        pte->pte,
        lpte.pte);

    *pte = lpte;

    flush_tlb_all();
    spin_unlock_irqrestore(&pfa_em_mut, flags);
    return 0;
  } else {
    return -2;
  }
}
#endif

int pfa_handle_fault(struct vm_fault *vmf)
{
  int nfetched;
  pfa_trace("Page fault received on remote page (vaddr=0x%lx) (tsk=%d) (pte=0x%lx)\n",
      vmf->address & PAGE_MASK,
      current->pfa_tsk_id,
      pte_val(*(vmf->pte)));
  pfa_stat_add(n_pfa_fault, 1, current);

  /* Note: we must already hold mm->mmap_sem or we could deadlock with kpfad */

  if(!is_pfa_tsk(current)) {
    pfa_trace("Page fault on remote page after PFA exited\n");
    return VM_FAULT_SIGBUS;
  }

  /* We should only see a fault with the PFA enabled if the queues need draining */
  /* It's OK to call these even if their queues don't need processing */
  /* Note: the order matters here. If you fill the freeq before draining
   * the newq, the frameq could overflow */
  nfetched = pfa_drain_newq(current->pfa_tsk_id);
  pfa_fill_freeq();
  pfa_stat_add(n_fault_fetched, nfetched, current);

#ifdef CONFIG_PFA_KPFAD
  kpfad_dec_sleep();
#endif

  /* Even if we didn't change the PTE, we must flush pte from the TLB
   * to trigger another PT walk (at least on Rocket) */
	update_mmu_cache(vmf->vma, vmf->address, vmf->pte);
  /* flush_tlb_all(); */

  /* pfa_unlock(global); */
  return 0;
}

void pfa_frameq_push(struct page *frame)
{
  pfa_assert_lock(global);

  PQ_PUSH(pfa_frameq, frame);
  return;
}

struct page* pfa_frameq_pop(void)
{
  struct page *ret;

  pfa_assert_lock(global);
  PQ_POP(pfa_frameq, ret);

  return ret;
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
    pfa_warn("Ran out of pfa task slots (only %d allowed)!\n", PFA_MAX_TASKS);
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
  // Hard-coded to only run on core 3 since experiments all run on core 2 
  // be sure to isolcpus=2,3 for best results
  set_cpus_allowed_ptr(kpfad_tsk, cpumask_of(3));
#endif
  return 1;
}

void pfa_clear_tsk(int tsk_id)
{
#if defined(CONFIG_PFA_DEBUG) && defined(CONFIG_PFA_EM)
  // Empty the debug hashtable
  int bkt;
  struct hlist_node *tmp;
  dbg_page_t *ent;
#endif
  PFA_ASSERT(tsk_id < PFA_MAX_TASKS && tsk_id >= 0, "Invalid task id: %d\n", tsk_id);
  PFA_ASSERT(pfa_tsk[tsk_id] != NULL, "No valid PFA task at tskid %d\n", tsk_id);
  pfa_trace("De-registering pfa task (tsk=%d)\n", tsk_id);

  pfa_lock(global);

#ifdef CONFIG_PFA_KPFAD
  kthread_stop(kpfad_tsk);
#endif

  pfa_drain_newq(-1);
  pfa_tsk[tsk_id]->pfa_tsk_id = -1;
  pfa_tsk[tsk_id] = NULL;

#if defined(CONFIG_PFA_DEBUG) && defined(CONFIG_PFA_EM)
  /* hash_for_each_safe(ent, tmp, pfa_dbg_page, _hash) { */
  hash_for_each_safe(pfa_dbg_page, bkt, tmp, ent, _hash) {
    hash_del(&(ent->_hash));
    hlist_add_head(&(ent->_hash), &(pfa_dbg_page_free));
  }
#endif

  pfa_trace("Done deregistering %d\n", tsk_id);
  pfa_unlock(global);

  return;
}

#ifdef CONFIG_PFA_KPFAD
/* PFA management daemon. Mostly drains newq and fills freeq. */
static int kpfad(void *p)
{
  struct mm_struct *mm;

  printk("kpfad started: (pid=%d) (cpu=%d)\n", task_tgid_vnr(current), smp_processor_id());

  //XXX I'm assuming max 1 PFA task at a time
  mm = pfa_get_tsk(0)->mm;
  while(1) {
    int nfetched;

    if (kthread_should_stop())
      break;

    if(pfa_read_newstat() != 0) {
      uint64_t start;
      down_read(&mm->mmap_sem);
      pfa_lock(global);

      start = pfa_stat_clock();
      /* Note: the order matters here. If you fill the freeq before draining
       * the newq, the frameq could overflow */
      nfetched = pfa_drain_newq(0);
      pfa_fill_freeq();

      pfa_unlock(global);
      up_read(&mm->mmap_sem);
      pfa_stat_add(n_kpfad_fetched, nfetched, NULL);
      pfa_stat_add(t_kpfad, pfa_stat_clock() - start, NULL);
    } else {
      /* we're effectively polling newstat */
      cpu_relax();
    }

    /* Keep kpfad running as long as it potentially has work to do */
    /* if(pfa_read_newstat() != 0) { */
    /*   #<{(| Not a big deal if we can't get the pfa_lock, just try again later  */
    /*      Some other code-paths take mmap_sem before grabbing pfa_global, this */
    /*    * could deadlock. We must grab them in this order. |)}># */
    /*   if(down_read_trylock(&mm->mmap_sem)) { */
    /*     if(pfa_trylock(global)) { */
    /*       uint64_t start = pfa_stat_clock(); */
    /*       #<{(| Note: the order matters here. If you fill the freeq before draining */
    /*        * the newq, the frameq could overflow |)}># */
    /*       nfetched = pfa_drain_newq(0); */
    /*       pfa_fill_freeq(); */
    /*  */
    /*       #<{(| Calculate next sleep time |)}># */
    /*       kpfad_inc_sleep(); */
    /*        */
    /*       pfa_unlock(global); */
    /*       pfa_stat_add(n_kpfad_fetched, nfetched, NULL); */
    /*       pfa_stat_add(t_kpfad, pfa_stat_clock() - start, NULL); */
    /*     } */
    /*     up_read(&mm->mmap_sem); */
    /*   } */
    /* } */
    /* } else { */
    /*   pfa_stat_add(n_kpfad, 1, NULL); */
    /*   usleep_range(kpfad_sleeptime, kpfad_sleeptime + KPFAD_SLEEP_SLACK); */
    /* } */

  }

  printk("kpfad exiting\n");
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

void pfa_init(uint64_t memblade_mac)
{
  /* Create sysfs interface
   * Don't fail on errors, User won't be able to use PFA, but we don't need
   * to crash the kernel either */
    if(sysfs_create_file(mm_kobj, &pfa_sysfs_tsk.attr) != 0)
          pr_err("Failed to create sysfs entries\n");
  
  return;
}
#endif
