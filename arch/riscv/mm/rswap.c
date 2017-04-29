#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/frontswap.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>

struct rswap_page {
  pgoff_t offset;
  struct rhash_head node;
  void *p; // holds the buffer where the evicted page's buffer will reside
};

static bool rswap_enabled;
static struct rhashtable ht;
static struct kmem_cache *rswap_page_cache;

static atomic_t debug_curr_rpages = ATOMIC_INIT(0);
static u64 debug_loaded_rpages;
static u64 debug_stored_rpages;
static u64 debug_invalidated_rpages;

static struct rhashtable_params htparams = {
  .head_offset = offsetof(struct rswap_page, node),
  .key_offset = offsetof(struct rswap_page, offset),
  .key_len = sizeof(pgoff_t),
  .automatic_shrinking = true,
};

module_param_named(enabled, rswap_enabled, bool, 0644);

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

  printk("\n\nRSWAP STORE RUNNING\n\n");

  /* return if the module hasn't been enabled */
  if (unlikely(!rswap_enabled))
    return -ENODEV;

  created_rpage = false;
  rpage = rhashtable_lookup_fast(&ht, &offset, htparams);

  /* if the offset didn't exist before, allocate a new rpage */
  if (likely(!rpage)) {
    rpage = kmem_cache_alloc(rswap_page_cache, GFP_KERNEL);
    if (unlikely(!rpage)) {
      pr_err("store: couldn't allocate rswap_page\n");
      return -ENOMEM;
    }
    rpage->p = (void *) __get_free_page(GFP_KERNEL);
    if (unlikely(!rpage->p)) {
      pr_err("store: could not allocate local storage for rpage->p\n");
      return -ENOMEM;
    }
    created_rpage = true;
  }

  /* populate rpage */
  rpage->offset = offset;

  /* get page vaddr and copy it to local buffer (rpage->p) */
  page_vaddr = kmap_atomic(page);
  memcpy(rpage->p, page_vaddr, PAGE_SIZE);
  kunmap_atomic(page_vaddr);

  /* if we just created the rpage, insert it into the ht */
  if (likely(created_rpage)) {
    if (rhashtable_insert_fast(&ht, &(rpage->node), htparams)) {
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

  printk("\n\n RSWAP LOAD RUNNING\n\n");

  /* find page */
  rpage = rhashtable_lookup_fast(&ht, &offset, htparams);
  if (unlikely(!rpage)) {
    pr_err("load: rpage load failed, not found\n");
    return -1;
  }

  /* copy rpage->p to page vaddr */
  page_vaddr = kmap_atomic(page);
  memcpy(page_vaddr, rpage->p, PAGE_SIZE);
  kunmap_atomic(page_vaddr);

  debug_loaded_rpages++;
  return 0;
}

static void rswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
  struct rswap_page *rpage;

  printk("\n\nRSWAP INVALIDATE PAGE RUNNING\n\n");

  rpage = rhashtable_lookup_fast(&ht, &offset, htparams);
  /* page not in ht anymore, maybe loaded, return */
  if (!rpage)
    return;

  free_page((unsigned long) rpage->p);

  /* remove rpage from ht and cache */
  if (unlikely(rhashtable_remove_fast(&ht, &(rpage->node), htparams)))
    pr_err("invalidate: couldn't remove rpage from ht\n");

  kmem_cache_free(rswap_page_cache, rpage);
  atomic_dec(&debug_curr_rpages);
  debug_invalidated_rpages++;
}

static void rswap_frontswap_invalidate_area(unsigned type)
{
  printk("\n\nRSWAP INVALIDATE AREA \n\n");

  pr_err("rswap_frontswap_invalidate_area\n");
}

static void rswap_frontswap_init(unsigned type)
{
  int err;
  printk("\n\nRSWAP FRONTSWAP INIT\n\n");

  pr_err("rswap_frontswap_init start\n");
  err = rhashtable_init(&ht, &htparams);
  if (err < 0) {
    pr_err("cannot allocate ht\n");
    return;
  }

  rswap_page_cache = KMEM_CACHE(rswap_page, 0);
  if (!rswap_page_cache) {
    pr_err("cannot callocate rswap_page_cache\n");
    return;
  }

  pr_err("rswap_frontswap_init end\n");
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
  printk("\n\n RSWAP DEBUGFS INIT\n\n");
  struct dentry *root = debugfs_create_dir("rswap", NULL);
  if (!root)
    return -ENXIO;
  debugfs_create_atomic_t("curr_rpages", S_IRUGO, root, &debug_curr_rpages);
  debugfs_create_u64("loaded_rpages", S_IRUGO, root, &debug_loaded_rpages);
  debugfs_create_u64("stored_rpages", S_IRUGO, root, &debug_stored_rpages);
  debugfs_create_u64("invalidated_rpages", S_IRUGO, root, &debug_invalidated_rpages);

  return 0;
}

static int __init init_rswap(void)
{
  printk("\n\n RSWAP INIT\n\n");

  frontswap_register_ops(&rswap_frontswap_ops);
  if (rswap_init_debugfs())
    pr_warn("rswap debugfs failed\n");

  pr_err("rswap module loaded\n");
  return 0;
}

late_initcall(init_rswap);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UCB");
MODULE_DESCRIPTION("Experiments");
