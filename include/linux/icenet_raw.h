#include <linux/io.h>

typedef struct icenic {
	struct device *dev;
	void __iomem *iomem;
  size_t sendq_max;
  size_t recvq_max;
} icenic_t;

/* Send a segment out the NIC.
 * last: true if this is the last segment in packet, false otherwise
 * paddr: must be 8-byte aligned
 * len: must be multiple of 8
 */
void ice_post_send(icenic_t *nic, bool last, uintptr_t paddr, size_t len);

/* Blocks until there are no more pending sends */
void ice_drain_sendq(icenic_t *nic);

/* Give the buffer at paddr to the NIC to receive into.
 * buffer must be > MTU (XXX???) */
void ice_post_recv(icenic_t *nic, uintptr_t paddr);

/* Wait until exactly one packet is received. */
size_t ice_recv_one(icenic_t *nic);

/* Initialize the nic and give you a handle for it */
icenic_t *ice_init(void);
