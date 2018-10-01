#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/frontswap.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/delay.h>
#include <linux/pfa.h>
#include <linux/pfa_stat.h>
#include <linux/memblade_client.h>
#include <linux/icenet_raw.h>

icenic_t *nic;
spinlock_t rmem_mut;
uint16_t txid;

/* static int pg_cmp(uint64_t *p1, uint64_t *p2) */
/* { */
/*   int i; */
/*   for(i = 0; i < 4096 / sizeof(uint64_t); i++) */
/*   { */
/*     if(p1[i] != p2[i]) { */
/*       printk("Pages mismatch at index %d (%llx != %llx)\n", i, p1[i], p2[i]); */
/*       return 0; */
/*     } */
/*   } */
/*   return 1; */
/* } */

/* Use memblade client HW to directly put a page into rmem */
static void rmem_put(uintptr_t src_paddr, uint32_t pgid)
{
  unsigned long irq;
  spin_lock_irqsave(&rmem_mut, irq);

  mb_send(src_paddr, (uintptr_t)NULL, MB_OC_PAGE_WRITE, pgid);
  mb_wait();
  
  spin_unlock_irqrestore(&rmem_mut, irq);
}

static void rmem_get(uintptr_t dest_paddr, uint32_t pgid)
{
  unsigned long irq;
  spin_lock_irqsave(&rmem_mut, irq);
  mb_send((uintptr_t)NULL, dest_paddr, MB_OC_PAGE_READ, pgid);
  mb_wait();
  spin_unlock_irqrestore(&rmem_mut, irq);
}

/* This is a unit test for the RMEM interface. You don't need (and probably
 * shouldn't) run this normally */
static int rmem_unit_test(void)
{
  int i;
  uint64_t put_start, get_start, put_cycles, get_cycles;
  /* uint64_t *pg = kmalloc(4096, GFP_KERNEL); */
  uint64_t *pg = (uint64_t*)__get_free_page(GFP_KERNEL);
  for(i = 0; i < (4096 / 8); i++) {
    pg[i] = 0xDEADBEEFCAFEBABE;
  }

  put_start = pfa_stat_clock();
  rmem_put(virt_to_phys(pg), 0);
  put_cycles = pfa_stat_clock() - put_start;

  /* Reset values (to detect memory corruption */
  for(i = 0; i < (4096 / 8); i++) {
    pg[i] = 0xAAAABBBBCCCCDDDD;
  }

  get_start = pfa_stat_clock();
  rmem_get(virt_to_phys(pg), 0);
  get_cycles = pfa_stat_clock() - get_start;
   for(i = 0; i < (4096 / 8); i++) {
    if(pg[i] != 0xDEADBEEFCAFEBABE) {
      printk("RMEM unit test failure;");
      return 0;
    }
  }
 
  free_page((uintptr_t)pg);
  printk("RMEM Put: %lld cycles\nRMEM Get: %lld cycles\n", put_cycles,
      get_cycles);
  return 1;
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
  uint64_t start;

#ifdef CONFIG_PFA
  /* Strictly speaking, this isn't really needed (we could evict using rmem),
   * however, rmem can race with the pfa to access the NIC, so it's safer to
   * serialize these accesses through the PFA */
  pfa_evict(pfa_swp_to_rpn(swp_entry(type, offset)), page_to_phys(page));
  return 0;
#endif

  /* Default is to use memblade */
  start = pfa_stat_clock();
  rmem_put(page_to_phys(page), pfa_swp_to_rpn(swp_entry(type, offset)));
  pfa_stat_add(t_rmem_write, pfa_stat_clock() - start, NULL);
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
  uint64_t start;

  pfa_trace("frontswap_load rpn=0x%llx dest_paddr=0x%llx\n",
      pfa_swp_to_rpn(swp_entry(type,offset)), page_to_phys(page));
  start = pfa_stat_clock();
  rmem_get(page_to_phys(page), pfa_swp_to_rpn(swp_entry(type,offset)));
  pfa_stat_add(t_rmem_read, pfa_stat_clock() - start, NULL);
  pfa_stat_add(n_fetched, 1, NULL);
	return 0;
}

static void rswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
  /* Hopefully it's OK to never invalidate stuff? I'm not even sure what that
   * would really mean... */
  return;
}

static void rswap_frontswap_invalidate_area(unsigned type)
{
  return;
  /* pr_err("rswap_frontswap_invalidate_area\n"); */
}

static void rswap_frontswap_init(unsigned type)
{
  spin_lock_init(&rmem_mut);
  mb_init();

  printk("Running memory blade unit test\n");
  if(!rmem_unit_test()) {
    printk("RMEM doesn't work, don't swap you fools!!!\n");
  }

#ifdef CONFIG_PFA
  nic = ice_init();
  pfa_init(nic->mac);
#endif

  pfa_stat_init();

  pr_info("rswap_frontswap_init end\n");
}

static struct frontswap_ops rswap_frontswap_ops = {
  .store = rswap_frontswap_store,
  .load = rswap_frontswap_load,
  .invalidate_page = rswap_frontswap_invalidate_page,
  .invalidate_area = rswap_frontswap_invalidate_area,
  .init = rswap_frontswap_init,
};

static int __init init_rswap(void)
{
  // XXX This is the wrong way to do this, in later versions Emmanuel turned
  // this into a kernel module, which I think is the right way.
  // Fixes compilation issue if frontswap isn't enabled
#ifdef CONFIG_FRONTSWAP
  frontswap_register_ops(&rswap_frontswap_ops);
#endif

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
