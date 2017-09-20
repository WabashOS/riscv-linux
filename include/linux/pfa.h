#ifndef _PFA_HELPER_H
#define _PFA_HELPER_H

#include <asm/page.h>
#include <asm/pgtable.h>
// #include <asm/pgtable-bits.h>
#include <linux/swap.h>
#include <linux/swapops.h>

extern pid_t pfa_pid;
extern unsigned long pfa_addr;

#define USE_PFA

/* Remote PTE */
#define PFA_PGID_SHIFT 12
#define PFA_PROT_SHIFT   2

/* Use this for noisy messages you might want to turn off */
#define pfa_trace(M, ...) printk("PFA_TRACE: " M, ##__VA_ARGS__)
// #define pfa_trace(M, ...) 

/* pgid is a compressed form of swp_entry_t. It assumes that type=0 and then
 * just uses the offset as pgid */
typedef uint64_t pfa_pgid_t;
/* Maximum size of a PageID (in bits) */
#define PFA_PGID_BITS (sizeof(pte_t)*8 - PFA_PGID_SHIFT)

static inline uint64_t get_cycle(void)
{
  register unsigned long __v;
  __asm__ __volatile__ ("rdcycle %0" : "=r" (__v));
  return __v;
}

/* initialize the system, only call once! */
void pfa_init(void);

/* Evict a page to the pfa.
 * ptep - paddr of pte for the page to be evicted
 */
void pfa_evict(uintptr_t vaddr, uintptr_t page_paddr);

/* Add the frame at pfn to the list of free frames for the pfa.
 * pfn - the page frame number to be added 
 */
void pfa_free(unsigned long pte_paddr);

/* Fetch and report every newpage from PFA */
void pfa_new(void);

/* Provides enough free frames to the PFA to fill it's queues */
void pfa_fill_freeq(void);

/* Handle a page fault due to PFA error (remote bit set in PTE) */
int pfa_handle_fault(struct vm_fault *vmf);

/* Translate any virtual address to it's physical address 
 * note the kernel virt_to_phys only works for kernel addresses
 * pte: PTE of vaddr to translate
 * vaddr: virtual address to translate
 */
static inline uintptr_t pfa_vaddr_to_paddr(pte_t pte, uintptr_t vaddr)
{
  return (pte_pfn(pte) << PAGE_SHIFT) +
         (vaddr & ~(~0ul << PAGE_SHIFT));
}

/* Convert a swp entry to a pfa pageID */
static inline pfa_pgid_t pfa_swp_to_pgid(swp_entry_t ent)
{
  pgoff_t off;
  /* This is pretty hacky. We assume 2 things:
   * 1. Linux always uses the first swp device when evicting to PFA (probably
   *    safe so long as it never fills up from non-PFA swap activity)
   * 2. Linux swap offset only uses page_id bits (52). Probably safe since the
   *    offset seems to be a monotonically increasing set of blockIDs (would need
   *    to swap out PBs of data to overflow
   */
  BUG_ON(swp_type(ent) != 0);
  off = swp_offset(ent);
  BUG_ON(off >= (1ul << PFA_PGID_BITS));
  return off;
}

/* Create a swp_entry_t from a pgid */
static inline swp_entry_t pfa_pgid_to_swp(pfa_pgid_t pgid)
{
  return swp_entry(0, pgid);
}

/* Create a remote pte */
static inline pte_t pfa_mk_remote_pte(swp_entry_t swp_ent, pgprot_t prot)
{
  pfa_pgid_t pgid = pfa_swp_to_pgid(swp_ent);
  return __pte(
        (pgid << PFA_PGID_SHIFT) |
        (pgprot_val(prot) << PFA_PROT_SHIFT) |
        _PAGE_REMOTE
       );
}

#endif
