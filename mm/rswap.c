#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/frontswap.h>
#include <linux/rhashtable.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pfa.h>

#undef RSWAP_DEBUG

#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 1) /* must match what server is allocating */
#define RPAGE_SIZE (4096)
#define NUM_RSWAP_PAGES (REMOTE_BUF_SIZE / RPAGE_SIZE)
/* #define HT_NELEM_HINT (NUM_RSWAP_PAGES * 0.75) */
#define HT_NELEM_HINT ((1<<16) - 1)

/* describes pages available on the remote side */
struct rswap_page {
  pgoff_t offset; /* offset in local virtual memory */
  struct rhash_head ht_node;
  struct list_head l_node; /* keeps track of available rswap_pages */
  u64 roffset; /* the offset in the remote memory buffer */
  void *drambuf;
};

static struct rhashtable page_ht;
static struct list_head page_head;
static spinlock_t list_lock;

static atomic_t debug_curr_rpages = ATOMIC_INIT(0);
static u64 debug_free_rpages; /* only modified within spinlock */
static u64 debug_loaded_rpages;
static u64 debug_stored_rpages;
static u64 debug_invalidated_rpages;
static u64 debug_cpu0;
static u64 debug_cpu1;
static u64 debug_cpu2;
static u64 debug_cpu3;

static struct rhashtable_params htparams = {
  .head_offset = offsetof(struct rswap_page, ht_node),
  .key_offset = offsetof(struct rswap_page, offset),
  .key_len = sizeof(pgoff_t),
  .automatic_shrinking = false,
  .nelem_hint = HT_NELEM_HINT,
  .max_size = NUM_RSWAP_PAGES,
};

static inline void debug_add_cpu_usage(int cpu)
{
#ifdef RSWAP_DEBUG
  switch (cpu) {
  case 0:
    debug_cpu0++;
    break;
  case 1:
    debug_cpu1++;
    break;
  case 2:
    debug_cpu2++;
    break;
  case 3:
    debug_cpu3++;
    break;
  default:
    pr_err("unknown cpu: %d\n", cpu);
  }
#endif
}

/*
 * returns a free rswap_page
 * this will remove the rswap_page from the queue
 */
static struct rswap_page *get_free_rpage(void)
{
  struct rswap_page *p;

  if (unlikely(list_empty(&page_head))) {
    pr_err("there are no free rswap_pages\n");
    return NULL;
  }

  spin_lock_irq(&list_lock);
  p = list_entry(page_head.next, struct rswap_page, l_node);
  list_del_init(&(p->l_node));
  spin_unlock_irq(&list_lock);

  debug_free_rpages--;
  return p;
}

/* marks the rswap_page as available, put it back on the queue */
static void put_free_rpage(struct rswap_page *p)
{
  spin_lock_irq(&list_lock);
  list_add_tail(&(p->l_node), &page_head);
  spin_unlock_irq(&list_lock);

  debug_free_rpages++;
}

/* initializes the rswap_pages  */
static void init_rswap_pages(u64 buffersize)
{
  unsigned int num_rpages = buffersize / PAGE_SIZE;
  struct rswap_page *rpage;
  unsigned int i;

  INIT_LIST_HEAD(&page_head);
  spin_lock_init(&list_lock);

  /* allocate as many rswap_page's as we have remote pages */
  for (i = 0; i < num_rpages; ++i) {
    rpage = kzalloc(sizeof(struct rswap_page), GFP_KERNEL);
    if (!rpage) {
      pr_err("init_rswap_pages: could not allocate rswap_page\n");
    }
    rpage->roffset = PAGE_SIZE * i;
    rpage->drambuf = (void *) __get_free_page(GFP_KERNEL);
    list_add_tail(&(rpage->l_node), &page_head);
    debug_free_rpages++;
  }

  if (rhashtable_init(&page_ht, &htparams) < 0) {
    pr_err("cannot allocate page_ht\n");
  }
}

/*
 * return 0 if page is stored
 * return error otherwise
 * the function should check if the page is already present. if it is, replace
 * its contents with the new page.
 */
static int rswap_frontswap_store(unsigned type, pgoff_t offset,
        struct page *page)
{
  struct rswap_page *rpage;
  void *page_vaddr;
  bool created_rpage;
  int cpu;

#ifdef USE_PFA
  int mapcount = atomic_read(&(page->_mapcount));
  if(mapcount > 1) {
    printk("Page mapped %d times\n", mapcount);
  }

  /* for PFA, we actually store the page during try_to_unmap_one */
  return 0;
#endif

  created_rpage = false;
  rpage = rhashtable_lookup_fast(&page_ht, &offset, htparams);

  /* if the offset didn't exist before, allocate a new rpage */
  if (likely(!rpage)) {
    rpage = get_free_rpage();
    created_rpage = true;
  } else {
    /* TODO: think about what should happen with the remote buffer
     * when the page already exists */
    pr_err("page already existed\n");
  }

  /* populate rpage */
  rpage->offset = offset;

  /* store page remotely */
  cpu = get_cpu();
  debug_add_cpu_usage(cpu);
  page_vaddr = kmap_atomic(page);
  memcpy(rpage->drambuf, page_vaddr, PAGE_SIZE);
  kunmap_atomic(page_vaddr);
  put_cpu();

  /* if we just created the rpage, insert it into the page_ht */
  if (likely(created_rpage)) {
    if (unlikely(rhashtable_insert_fast(&page_ht, &(rpage->ht_node), htparams))) {
      pr_err("store: page insertion failed\n");
      return -ENODEV;
    }
    atomic_inc(&debug_curr_rpages);
  }
  debug_stored_rpages++;
  return 0;
}

/*
 * return 0 if page is returned
 * return -1 otherwise
 * according to frontswap, we shouldn't remove the rpage after
 * a load.
 */
static int rswap_frontswap_load(unsigned type, pgoff_t offset,
        struct page *page)
{
  struct rswap_page *rpage;
  void *page_vaddr;
  int cpu;

#ifdef USE_PFA
  /* When using the PFA, the page data was already fetched. Do nothing here.*/
  return 0;
#endif

  /* find page */
  rpage = rhashtable_lookup_fast(&page_ht, &offset, htparams);

#ifdef RSWAP_DEBUG
  if (unlikely(!rpage)) {
    pr_err("load: rpage load failed, not found\n");
    return -1;
  }
#endif

  cpu = get_cpu();
  debug_add_cpu_usage(cpu);
  page_vaddr = kmap_atomic(page);
  memcpy(page_vaddr, rpage->drambuf, PAGE_SIZE);
  kunmap_atomic(page_vaddr);
  put_cpu();

  debug_loaded_rpages++;
  return 0;
}

static void rswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
  struct rswap_page *rpage;

#ifdef USE_PFA
  /* Hopefully it's OK to never invalidate stuff? I'm not even sure what that
   * would really mean... */
  return;
#endif

  rpage = rhashtable_lookup_fast(&page_ht, &offset, htparams);

#ifdef RSWAP_DEBUG
  /* page not in page_ht anymore, return */
  if (unlikely(!rpage)) {
    pr_err("invalidate: did not find page\n");
    return;
  }
#endif

  /* remove rpage from page_ht and cache */
  if (unlikely(rhashtable_remove_fast(&page_ht, &(rpage->ht_node), htparams)))
    pr_err("invalidate: couldn't remove rpage from page_ht\n");

  put_free_rpage(rpage);
  atomic_dec(&debug_curr_rpages);
  debug_invalidated_rpages++;
}

static void rswap_frontswap_invalidate_area(unsigned type)
{
#ifdef USE_PFA
  return;
#endif
  pr_err("rswap_frontswap_invalidate_area\n");
}

static void rswap_frontswap_init(unsigned type)
{
  init_rswap_pages(REMOTE_BUF_SIZE);
#ifdef USE_PFA
  pfa_init();
#endif

  pr_info("rswap_frontswap_init end\n");
}

static struct frontswap_ops rswap_frontswap_ops = {
  .store = rswap_frontswap_store,
  .load = rswap_frontswap_load,
  .invalidate_page = rswap_frontswap_invalidate_page,
  .invalidate_area = rswap_frontswap_invalidate_area,
  .init = rswap_frontswap_init,
};

static int __init rswap_init_debugfs(void)
{
  struct dentry *root = debugfs_create_dir("rswap", NULL);
  if (!root)
    return -ENXIO;
  debugfs_create_atomic_t("curr_rpages", S_IRUGO, root, &debug_curr_rpages);
  debugfs_create_u64("free_rpages", S_IRUGO, root, &debug_free_rpages);
  debugfs_create_u64("loaded_rpages", S_IRUGO, root, &debug_loaded_rpages);
  debugfs_create_u64("stored_rpages", S_IRUGO, root, &debug_stored_rpages);
  debugfs_create_u64("invalidated_rpages", S_IRUGO, root, &debug_invalidated_rpages);
  debugfs_create_u64("cpu0", S_IRUGO, root, &debug_cpu0);
  debugfs_create_u64("cpu1", S_IRUGO, root, &debug_cpu1);
  debugfs_create_u64("cpu2", S_IRUGO, root, &debug_cpu2);
  debugfs_create_u64("cpu3", S_IRUGO, root, &debug_cpu3);

  return 0;
}

static int __init init_rswap(void)
{
  frontswap_register_ops(&rswap_frontswap_ops);
  if (rswap_init_debugfs())
    pr_err("rswap debugfs failed\n");

  pfa_init();

  pr_info("rswap module loaded\n");
  return 0;
}

static void __exit exit_rswap(void)
{
  pr_info("unloading rswap\n");
}

module_init(init_rswap);
module_exit(exit_rswap);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("UCB");
MODULE_DESCRIPTION("Experiments");
