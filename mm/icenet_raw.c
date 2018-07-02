#include <linux/icenet_raw.h>
#include <linux/slab.h>

#define ICENET_NAME "icenet"
#define ICENET_IO_BASE  0x10016000
#define ICENET_SEND_REQ 0
#define ICENET_RECV_REQ 8
#define ICENET_SEND_COMP 16
#define ICENET_RECV_COMP 18
#define ICENET_COUNTS 20
#define ICENET_MACADDR 24
#define ICENET_IO_SIZE 32

#define CIRC_BUF_LEN 16
#define ALIGN_BYTES 8
#define ALIGN_MASK 0x7
#define ALIGN_SHIFT 3
#define MAX_FRAME_SIZE (190 * ALIGN_BYTES)
#define DMA_PTR_ALIGN(p) ((typeof(p)) (__ALIGN_KERNEL((uintptr_t) (p), ALIGN_BYTES)))
#define DMA_LEN_ALIGN(n) (((((n) - 1) >> ALIGN_SHIFT) + 1) << ALIGN_SHIFT)
#define MACADDR_BYTES 6

static inline int send_req_avail(icenic_t *nic)
{
	return ioread16(nic->iomem + ICENET_COUNTS) & 0xf;
}

static inline int recv_req_avail(icenic_t *nic)
{
	return (ioread16(nic->iomem + ICENET_COUNTS) >> 4) & 0xf;
}

static inline int send_comp_avail(icenic_t *nic)
{
	return (ioread16(nic->iomem + ICENET_COUNTS) >> 8) & 0xf;
}

static inline int recv_comp_avail(icenic_t *nic)
{
	return (ioread16(nic->iomem + ICENET_COUNTS) >> 12) & 0xf;
}

void ice_post_send(icenic_t *nic, bool last, uintptr_t paddr, size_t len)
{
	uint64_t command = 0;

  if( ((paddr & 0x7ll) != 0) ||
      ((len % 8) != 0)) {
    printk("paddr: 0x%lx, len = 0x%lx\n", paddr, len);
    panic("Mis-aligned packet");
  }
	command = (len << 48) | (paddr & 0xffffffffffffL);
  command |= last ? 0 : (1ul << 63);

	iowrite64(command, nic->iomem + ICENET_SEND_REQ);
}

void ice_drain_sendq(icenic_t *nic)
{
  /* Poll until there are no more pending sends */
  while(send_req_avail(nic) < nic->sendq_max) { 
    cpu_relax();
  }

  /* Drain send_compq */
 	while (send_comp_avail(nic) > 0) {
		ioread16(nic->iomem + ICENET_SEND_COMP);
  }

  return;
}

void ice_post_recv(icenic_t *nic, uintptr_t paddr)
{
  if((paddr & 0x7) != 0) {
    panic("Unaligned receive buffer: %lx\n", paddr);
  }
	iowrite64(paddr, nic->iomem + ICENET_RECV_REQ);
}

size_t ice_recv_one(icenic_t *nic)
{
  /* Wait for there to be something in the recv_comp Q */
  while(recv_comp_avail(nic) == 0) { cpu_relax(); }

  /* Pop exactly one thing off Q */
  return (size_t)ioread16(nic->iomem + ICENET_RECV_COMP);
}

icenic_t *ice_init(void)
{
  printk("Initializing raw ice nic\n");
  icenic_t *nic = kmalloc(sizeof(icenic_t), GFP_KERNEL);

  /* XXX init iomem */
  nic->iomem = ioremap(ICENET_IO_BASE, ICENET_IO_SIZE);

  /* Initialize size of sendQ (used for completion polling) */
  nic->recvq_max = recv_req_avail(nic);
  nic->sendq_max = send_req_avail(nic);

  nic->mac = ioread64(nic->iomem + ICENET_MACADDR);

  return nic;
}
