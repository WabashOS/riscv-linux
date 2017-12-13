#include <linux/icenet_raw.h>
#include <linux/kernel.h>
#include <linux/remote_scratchpad.h>
#include <linux/rmem_eth.h>
#include <linux/rmem_proto.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>

icenic_t *nic = NULL;
MemBladeMetadata *blade = NULL;
spinlock_t rmem_mut;

// TODO(growly): Fetch our MAC address from the icenic.
uint8_t our_mac[] = {0xca, 0xfe, 0xfe, 0xed, 0xbe, 0xef};

static void _list_init(SimpleList *list) {
  list->front = NULL;
  list->back = NULL;
}

static void _list_enqueue(SimpleList *list, void *ptr) {
  SimpleListNode *node = kcalloc(1, sizeof(SimpleListNode), 1);
  node->ptr = ptr;
  if (list->front == NULL) {
    list->front = node;
    list->back = node;
  } else {
    list->back->next = node;
    list->back = node;
  }
}

static void _list_free_all(SimpleList *list) {
  SimpleListNode *next_header;
  while (list->front != NULL) {
    kfree(list->front->ptr);
    next_header = list->front->next;
    kfree(list->front);
    list->front = next_header;
  }
  list->front = NULL;
  list->back = NULL;
}

// Store n pages' worth of data from *src (a physical address) at consecutive
// blocks starting from block_id.
static void rmem_remote_set_one_block(uint8_t *src_paddr, block_id_t block_id) {
  SimpleList headers; 
  unsigned long flags;
  size_t data_to_request = 0;
  uint8_t part = 0;
  uint8_t *header = NULL;

  _list_init(&headers);

  // TODO(growly): Is this locking too aggressive?
  spin_lock_irqsave(&rmem_mut, flags);

  data_to_request = blade->block_size_bytes;
  part = 0;
  while (data_to_request > 0) {
    // Build header to send remaining bytes.
    uint8_t *header = (uint8_t*)kcalloc(
        RMEM_REQUEST_HEADER_SIZE_BYTES, sizeof(uint8_t), 0);

    // Manage header list.
    _list_enqueue(&headers, header);

    uint32_t transaction_id = blade->next_transaction_id++;
    size_t payload_size = min(data_to_request, RMEM_MAX_PAYLOAD_BYTES);
    size_t src_index = part * RMEM_MAX_PAYLOAD_BYTES;

    insert_ethernet_header(our_mac,
                           blade->mac_address,
                           kMemBladeRequestEtherType,
                           header);

    insert_request_header(RMEM_REQUEST_OP_PAGE_WRITE,
                          part,
                          block_id,
                          transaction_id,
                          header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

    ice_post_send(nic, false, virt_to_phys(header), RMEM_REQUEST_HEADER_SIZE_BYTES);
    ice_post_send(nic, true,  src_paddr + src_index, payload_size);

    printk("request op: %02x part: %u page: %u txn: %u payload %lu\n",
           RMEM_REQUEST_OP_PAGE_WRITE, part, block_id, transaction_id, payload_size);
     
    // TODO(growly): Have to make sure the entire packet is 8-byte aligned if
    // appending FCS.
    //append_ethernet_fcs(char *buffer, size_t length);

    // TODO(growly): We currently do no outstanding request tracking; if the
    // response isn't complete then we fail. There is only one send/receive
    // request thread. We can imitate the user-space version if this is the bottleneck.

    part++;
    data_to_request -= payload_size;
  }

  // Set up buffer for the response.
  header = kcalloc(
      RMEM_RESPONSE_HEADER_SIZE_BYTES + RMEM_MAX_PAYLOAD_BYTES,
      sizeof(uint8_t),
      0);

  _list_enqueue(&headers, header);

  ice_post_recv(nic, virt_to_phys(header));

  ice_drain_sendq(nic);

  ice_recv_one(nic);

  MemBladeResponseHeader *response = (MemBladeResponseHeader*)(
      header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

  printk("blade response: ver: %02x code: %02x txn: %u part: %u",
         response->common.version, response->common.code,
         response->transaction_id, response->part_id);

  spin_unlock_irqrestore(&rmem_mut, flags);

  /* Rate limit ourselves to avoid overwhelming the memory blade */
  //pfa_limit_evict();
  //start = pfa_stat_clock();
  //end = pfa_stat_clock();
  /* printk("Started sending at: %lld\n", start); */
  /* printk("Send completions at: %lld\n", end); */

  // Free all headers and all list entries.
  _list_free_all(&headers);
  
  return;
}

static void rmem_remote_set(
    uint8_t *base_paddr, block_id_t base_block_id, size_t n) {
  size_t i = 0;
  for (; i < n; ++i) {
    uint8_t *src_paddr = base_paddr + i * blade->block_size_bytes;
    block_id_t block_id = base_block_id + i;
    rmem_remote_set_one_block(virt_to_phys(src_paddr), block_id);
  }
}


static void rmem_remote_get_one_block(
    uint8_t *dst_paddr, block_id_t block_id) {
  unsigned long flags;
  uint8_t *header = NULL;
  int num_packets_expected = 0;
  size_t base_offset = 0;
  uint32_t transaction_id = 0;

  // TODO(growly): Hmmmm. Shouldn't this mutex be shared?
  spin_lock_irqsave(&rmem_mut, flags);

  header = kcalloc(RMEM_REQUEST_HEADER_SIZE_BYTES, sizeof(uint8_t), 0);

  insert_ethernet_header(our_mac,
                         blade->mac_address,
                         kMemBladeRequestEtherType,
                         header);

  transaction_id = blade->next_transaction_id++;
  // TODO(growly): What should the part_id be? 0xFF?
  insert_request_header(RMEM_REQUEST_OP_PAGE_WRITE,
                        0,
                        block_id,
                        transaction_id,
                        header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

  // Give the NIC buffers to receive into.
  while (base_offset < blade->block_size_bytes) {
    ice_post_recv(nic, dst_paddr + base_offset);
    base_offset += RMEM_MAX_PAYLOAD_BYTES;
    ++num_packets_expected;
  }

  /* printk("rmem_get txid %d, pgid %d\n", txid, pgid); */
  ice_post_send(nic, true, virt_to_phys(header), 8);

  printk("request op: %02x part: %u page: %u txn: %u num_packets_expected %d\n",
         RMEM_REQUEST_OP_PAGE_READ, 0, block_id, transaction_id,
         num_packets_expected);

  ice_drain_sendq(nic);
 
  /* Block until all packets received */
  while (num_packets_expected > 0) {
    ice_recv_one(nic);
    --num_packets_expected;
  }

  spin_unlock_irqrestore(&rmem_mut, flags);

  kfree(header);
  return;
}

static void rmem_remote_get(
    uint8_t *base_paddr, block_id_t base_block_id, size_t n) {
  size_t i = 0;
  for (; i < n; ++i) {
    uint8_t *dst_paddr = base_paddr + i * blade->block_size_bytes;
    block_id_t block_id = base_block_id + i;
    rmem_remote_get_one_block(dst_paddr, block_id);
  }
}

void remote_init(uint8_t *blade_mac,
                 size_t block_size_bytes,
                 size_t num_blocks) {
  BUG_ON(blade != NULL || nic != NULL);
  blade = kcalloc(sizeof(MemBladeMetadata), sizeof(uint8_t), 0);
  spin_lock_init(&rmem_mut);
  nic = ice_init();
}

void remote_destroy() {
  BUG_ON(blade == NULL);
  kfree(blade);
  blade = NULL;
  nic = NULL;
}

void remote_get(block_id_t src_block_id, void *dst, size_t n) {
  rmem_remote_get(virt_to_phys(dst), src_block_id, n);
}

void remote_set(void *src, block_id_t dst_block_id, size_t n) {
  rmem_remote_set(virt_to_phys(src), dst_block_id, n);
}
