#include "linux/memblade_client.h"
#include <linux/io.h>
#include <linux/highmem.h>

// XXX PFA - this is kinda janky because it's declared in pfa.h which we can't include here due to circular dependency...
extern spinlock_t pfa_hw_mut;

#ifdef CONFIG_MEMBLADE_EM

// Global, pre-allocated 'remote memory' to be used in emulation mode
uint8_t *mb_rmem;
spinlock_t mb_mut;

// Global txid (increases monotonically)
int mb_txid = -1;

/* Returns a reference to the 'remote' page corresponding to pageno.
 * This page is somewhere in addressable space and can be freely
 * read/written, no need to free or "put" the page after */
static uint8_t *mb_pg_get(uint64_t pageno)
{
  if(pageno >= MEMBLADE_NPG) {
    panic("Requested invalid remote page from memblade: %lld\n", pageno);
    return NULL;
  }
  return mb_rmem + (pageno*PAGE_SIZE);
}

static int mb_pg_read(uint64_t pageno, uintptr_t paddr)
{
  // Remote and user pages respecively
  uint8_t *rpg, *upg;
  
  rpg = mb_pg_get(pageno);
  if(!rpg) {
    return 0;
  }

  upg = kmap_atomic(phys_to_page(paddr));
  memcpy(upg, rpg, PAGE_SIZE);
  kunmap_atomic(upg);
  
  return 1;
}

static int mb_pg_write(uint64_t pageno, uintptr_t paddr)
{
  // Remote and user pages respecively
  uint8_t *rpg, *upg;
  
  rpg = mb_pg_get(pageno);
  if(!rpg) {
    return 0;
  }

  upg = kmap_atomic(phys_to_page(paddr));
  memcpy(rpg, upg, PAGE_SIZE);
  kunmap_atomic(upg);
  
  return 1;
}

static int mb_wd_read(uint64_t pageno, uintptr_t paddr)
{
  // Remote and user pages respecively
  uint8_t *rpg, *upg;
  off_t off = paddr - (paddr & PAGE_MASK);

  if((paddr & 0x111) != 0) {
    pr_err("Memblade word read to unaligned address: %lx\n", paddr);
  }

  rpg = mb_pg_get(pageno);
  if(!rpg) {
    return 0;
  }

  upg = kmap_atomic(phys_to_page(paddr));
  memcpy(upg + off, rpg + off, 8);
  kunmap_atomic(upg);
  
  return 1;
}

static int mb_wd_write(uint64_t pageno, uintptr_t paddr)
{
  // Remote and user pages respecively
  uint8_t *rpg, *upg;
  off_t off = paddr - (paddr & PAGE_MASK);

  if((paddr & 0x111) != 0) {
    pr_err("Memblade word write from unaligned address: %lx\n", paddr);
  }

  rpg = mb_pg_get(pageno);
  if(!rpg) {
    return 0;
  }

  upg = kmap_atomic(phys_to_page(paddr));
  memcpy(rpg + off, upg + off, 8);
  kunmap_atomic(upg);
  
  return 1;
}

int mb_send(
		uintptr_t src_paddr, uintptr_t dst_paddr,
		int opcode, uint64_t pageno)
{
  unsigned long irq;
  spin_lock_irqsave(&mb_mut, irq);

  if(!mb_rmem) {
    pr_err("Memory blade not initialized, ignoring request\n");
    return -1;
  }

  switch(opcode) {
    case MB_OC_PAGE_READ:
      if(!mb_pg_read(pageno, dst_paddr))
        return -1;
      break;
    case MB_OC_PAGE_WRITE:
      if(!mb_pg_write(pageno, src_paddr))
        return -1;
      break;
    case MB_OC_WORD_READ:
      if(!mb_wd_read(pageno, dst_paddr))
        return -1;
      break;
    case MB_OC_WORD_WRITE:
      if(!mb_wd_write(pageno, src_paddr))
        return -1;
      break;
    case MB_OC_ATOMIC_ADD:
      panic("Memblade atomic add not implemented\n");
      break;
    case MB_OC_COMP_SWAP:
      panic("Memblade comp/swap not implemented\n");
      break;
    default:
      panic("Unrecognized memory blade opcode: %d", opcode);
      break;
  }

  mb_txid++;
  spin_unlock_irqrestore(&mb_mut, irq);
  return mb_txid;
}

int mb_wait()
{
  return mb_txid;
}

void mb_init(uint64_t mb_mac)
{
  printk("Emulating memory blade at MAC: 0x%llx, size: %lld bytes\n", mb_mac, MEMBLADE_SZ);
  /* mb_rmem = (void*)__get_free_pages(GFP_KERNEL, get_order(MEMBLADE_SZ)); */
  mb_rmem = (void*)vmalloc(MEMBLADE_SZ);
  printk("Memblade vaddrs: 0x%llx - 0x%llx\n", mb_rmem, mb_rmem + MEMBLADE_SZ);
  if(!mb_rmem) {
    pr_err("Memory blade emulation failed to initialize.\n");
  }

  spin_lock_init(&mb_mut);
}

#else

void __iomem *mb_io_src;
void __iomem *mb_io_dst;
void __iomem *mb_io_mac;
void __iomem *mb_io_oc;
void __iomem *mb_io_pgno;
void __iomem *mb_io_req;
void __iomem *mb_io_nreq;
void __iomem *mb_io_resp;
void __iomem *mb_io_nresp;
uint64_t mb_dstmac;

int mb_send(
		uintptr_t src_paddr, uintptr_t dst_paddr,
		int opcode, uint64_t pageno)
{
  int res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);

	writeq(src_paddr, mb_io_src);
  writeq(dst_paddr, mb_io_dst);
  writeq(mb_dstmac, mb_io_mac);
  writeb(opcode, mb_io_oc);
  writeq(pageno, mb_io_pgno);

	while (readl(mb_io_nreq) == 0) {}
	asm volatile ("fence");
	res = readl(mb_io_req);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
  return res;
}

int mb_wait()
{
  int res;
  unsigned long flags;
  spin_lock_irqsave(&pfa_hw_mut, flags);

  while (readl(mb_io_nresp) == 0) {}
	asm volatile ("fence");
  res = readl(mb_io_resp);
  spin_unlock_irqrestore(&pfa_hw_mut, flags);
  return res;
}

void mb_init(uint64_t mb_mac)
{
  printk("Registering with memory blade at MAC: 0x%llx\n", mb_mac);
  mb_io_src   = ioremap(MB_SRC_ADDR, 8);
  mb_io_dst   = ioremap(MB_DST_ADDR, 8);
  mb_io_mac   = ioremap(MB_DSTMAC, 8);
  mb_io_oc    = ioremap(MB_OPCODE, 1);
  mb_io_pgno  = ioremap(MB_PAGENO, 8);
  mb_io_req   = ioremap(MB_REQ, 4);
  mb_io_nreq  = ioremap(MB_NREQ, 4);
  mb_io_resp  = ioremap(MB_RESP, 4);
  mb_io_nresp = ioremap(MB_NRESP, 4);

  /* Hard-coded for now for Spike loopback model, need to fix for real HW */
  /* mb_dstmac = CONFIG_MEMBLADE_MAC; */
  mb_dstmac = mb_mac;
}

#endif
