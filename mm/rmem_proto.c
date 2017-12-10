#include <linux/icenet_raw.h>
#include <linux/kernel.h>
#include <linux/remote_scratchpad.h>
#include <linux/rmem_eth.h>
#include <linux/rmem_proto.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

icenic_t *nic;
MemBladeMetadata *blade = NULL;

// TODO(growly): Fetch our MAC address from the icenic.
uint8_t our_mac[] = {0xca, 0xfe, 0xfe, 0xed, 0xbe, 0xef};

// TODO(growly): SimpleListNode management.
//static void _enqueue(SimpleListNode **prev, void *ptr) {
//  SimpleListNode *node = kcalloc(1, sizeof(SimpleListNode), 1);
//  node->ptr = ptr;
//  if (*prev == NULL) {
//    *prev = node;
//  } else {
//    (*prev)->next = node;
//  }
//
//}
//
//static SimpleListNode *_free_all(SimpleListNode *list) {
//}

// Store n pages' worth of data from *src (a physical address) at consecutive
// blocks starting from block_id.
static void rmem_remote_set_one_block(uint8_t *src_paddr, block_id_t block_id) {
  //unsigned long irq;
  //uint64_t start, end;
  
  //spin_lock_irqsave(&rmem_mut, irq);

  SimpleListNode *first_header = NULL, *last_header = NULL, *next_header = NULL;

  size_t data_to_request = blade->block_size_bytes;
  uint8_t part = 0;
  while (data_to_request > 0) {
    // Build header to send remaining bytes.
    uint8_t *header = (uint8_t*)kcalloc(
        RMEM_REQUEST_HEADER_SIZE_BYTES, sizeof(uint8_t), 0);

    // Manage header list.
    if (!first_header) {
      first_header = (SimpleListNode*)kcalloc(1, sizeof(SimpleListNode), 1);
      first_header->ptr = header;
      last_header = first_header;
    } else {
      next_header = (SimpleListNode*)kcalloc(1, sizeof(SimpleListNode), 1);
      next_header->ptr = header;
      last_header->next = next_header;
      last_header = next_header;
    }

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
     
    //size_t src_index = i * blade->block_size_bytes + part * MAX_PAYLOAD_BYTES;
    //memcpy(send_buffer + tx_len, src + src_index, payload_size);
    //tx_len += payload_size;

    // TODO(growly): Have to make sure the entire packet is 8-byte aligned if
    // appending FCS.
    //append_ethernet_fcs(char *buffer, size_t length);

    // Set up and insert the request data before the request is sent, so that
    // a quick response can't interleave.
    //MemBladeRequestMetadata *request =
    //    malloc(sizeof(MemBladeRequestMetadata));
    //assert(request != NULL);
    //request->data_expected_bytes = 0;
    //request->op_code = REQUEST_OP_WRITE;
    //request->transaction_id = transaction_id;
    //request->data_received_bytes = 0;
    //request->responses_received = 0;

    //pthread_mutex_lock(&request->lock);

    //HashTableInsert(blade->request_table, transaction_id, request);

    part++;
    data_to_request -= payload_size;

    //while (request->responses_received < 1) {
    //  pthread_cond_wait(&request->receipt_cond, &request->lock);
    //}
    //pthread_mutex_unlock(&request->lock);
  }

  // Set up buffer for the response.
  uint8_t *header = kcalloc(
      RMEM_RESPONSE_HEADER_SIZE_BYTES + RMEM_MAX_PAYLOAD_BYTES,
      sizeof(uint8_t),
      0);

  next_header = kcalloc(1, sizeof(SimpleListNode), 1);
  next_header->ptr = header;
  last_header->next = next_header;
  last_header = next_header;

  ice_post_recv(nic, virt_to_phys(header));

  ice_drain_sendq(nic);

  ice_recv_one(nic);

  MemBladeResponseHeader *response = (MemBladeResponseHeader*)(
      header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

  printk("blade response: ver: %02x code: %02x txn: %u part: %u",
         response->common.version, response->common.code,
         response->transaction_id, response->part_id);

  /* Rate limit ourselves to avoid overwhelming the memory blade */
  //pfa_limit_evict();

  //start = pfa_stat_clock();

  //end = pfa_stat_clock();
  /* printk("Started sending at: %lld\n", start); */
  /* printk("Send completions at: %lld\n", end); */

  /* ZCopy has to wait for completion (we could memcpy and then transmit
   * asynchronously, but...meh) */
  /* printk("rmem_put txid %d, pgid %d\n", txid, pgid); */
  //txid++;
  //spin_unlock_irqrestore(&rmem_mut, irq);

  //kfree(hdrs);

  // Free all headers and all list entries.
  while (first_header != NULL) {
    kfree(first_header->ptr);
    next_header = first_header->next;
    kfree(first_header);
    first_header = next_header;
  }
  last_header = NULL;
  
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
  //unsigned long irq;

  ///* I'm not sure I have to kmalloc this, but I'm too tired to think about it */
  //uint64_t *hdr = kmalloc(8, GFP_KERNEL);
  //PFA_ASSERT(hdr, "Failed to allocate rmem_get headers\n");
  //
  //spin_lock_irqsave(&rmem_mut, irq);
 
  //*hdr = ((uint64_t)pgid << 16) | txid;
  
  uint8_t *header = kcalloc(
      RMEM_REQUEST_HEADER_SIZE_BYTES, sizeof(uint8_t), 0);

  insert_ethernet_header(our_mac,
                         blade->mac_address,
                         kMemBladeRequestEtherType,
                         header);

  uint32_t transaction_id = blade->next_transaction_id++;

  // TODO(growly): What should the part_id be? 0xFF?
  insert_request_header(RMEM_REQUEST_OP_PAGE_WRITE,
                        0,
                        block_id,
                        transaction_id,
                        header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

  // Give the NIC buffers to receive into.

  int num_packets_expected = 0;
  size_t base_offset = 0;
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

  /* printk("rmem_got txid %d, pgid %d\n", txid, pgid); */
  //spin_unlock_irqrestore(&rmem_mut, irq);

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

void init_remote_memory(uint8_t *blade_mac,
                        size_t block_size_bytes,
                        size_t num_blocks) {
  BUG_ON(blade != NULL);
  blade = kcalloc(sizeof(MemBladeMetadata), sizeof(uint8_t), 0);
  nic = ice_init();
}

void destroy_remote_memory() {
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
