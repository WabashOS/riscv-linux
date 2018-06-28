#include "linux/memblade_client.h"
#include <linux/io.h>

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
	writeq(src_paddr, mb_io_src);
  writeq(dst_paddr, mb_io_dst);
  writeq(mb_dstmac, mb_io_mac);
  writeb(opcode, mb_io_oc);
  writeq(pageno, mb_io_pgno);

	while (readl(mb_io_nreq) == 0) {}
	/* asm volatile ("fence"); */
	return readl(mb_io_req);
}

int mb_wait()
{
  while (readl(mb_io_nresp) == 0) {}
  return readl(mb_io_resp);
}

void mb_init(void)
{
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
  mb_dstmac = CONFIG_MEMBLADE_MAC;
}
