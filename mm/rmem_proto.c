#include <linux/icenet_raw.h>
#include <linux/kernel.h>
#include <linux/pfa.h>
#include <linux/remote_scratchpad.h>
#include <linux/rmem_eth.h>
#include <linux/rmem_proto.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <uapi/linux/if_ether.h>

icenic_t *nic = NULL;
MemBladeMetadata *blade = NULL;
spinlock_t rmem_mut;

// TODO(growly): Fetch our MAC address from the icenic.
static uint8_t our_mac[] = {0x00, 0x12, 0x6D, 0x00, 0x00, 0x02}; // Slot 0
static uint8_t blade_mac[] = {0x00, 0x12, 0x6D, 0x00, 0x00, 0x03}; // Slot 1 

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
static void rmem_remote_set_one_block(uint8_t *src_vaddr, block_id_t block_id) {
  SimpleList send_headers; 
  SimpleList recv_headers; 
  SimpleListNode *next;
  unsigned long flags;
  size_t data_to_request = 0;
  uint8_t part = 0;
  uint8_t *send_header = NULL;
  uint8_t *recv_header = NULL;
  uint32_t transaction_id;
  size_t payload_size;
  size_t src_index;

  _list_init(&send_headers);
  _list_init(&recv_headers);

  // TODO(growly): Is this locking too aggressive?
  spin_lock_irqsave(&rmem_mut, flags);

  data_to_request = blade->block_size_bytes;
  part = 0;
  while (data_to_request > 0) {
    // Build header to send remaining bytes.
    send_header = (uint8_t*)kcalloc(
        RMEM_REQUEST_HEADER_SIZE_BYTES, sizeof(uint8_t), 0);
    // TODO(growly): Make an assertion or remove.
    if (!send_header) {
      printk("couldn't allocate send header!");
    }

    // Manage header list.
    _list_enqueue(&send_headers, send_header);

    // Set up buffer for the response.
    recv_header = kcalloc(
        RMEM_RESPONSE_HEADER_SIZE_BYTES + RMEM_MAX_PAYLOAD_BYTES,
        sizeof(uint8_t),
        0);

    _list_enqueue(&recv_headers, recv_header);

    transaction_id = blade->next_transaction_id++;
    payload_size = min(data_to_request, RMEM_MAX_PAYLOAD_BYTES);
    src_index = part * RMEM_MAX_PAYLOAD_BYTES;

    insert_ethernet_header(our_mac,
                           //blade->mac_address,
                           blade_mac,
                           kMemBladeRequestEtherType,
                           send_header + RMEM_BOGUS_ETH_H_PAD_BYTES);

    insert_request_header(RMEM_REQUEST_OP_PAGE_WRITE,
                          part,
                          block_id,
                          transaction_id,
                          send_header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

    printk("request op: %02x part: %u page: %u txn: %u payload %u\n",
           RMEM_REQUEST_OP_PAGE_WRITE, part, block_id, transaction_id,
           payload_size);
     
    ice_post_recv(nic, virt_to_phys(recv_header));

    ice_post_send(nic, false, virt_to_phys(send_header),
                  RMEM_REQUEST_HEADER_SIZE_BYTES);
    ice_post_send(nic, true, virt_to_phys(src_vaddr) + src_index,
                  payload_size);

    // TODO(growly): Have to make sure the entire packet is 8-byte aligned if
    // appending FCS.
    //append_ethernet_fcs(char *buffer, size_t length);

    // TODO(growly): We currently do no outstanding request tracking; if the
    // response isn't complete then we fail. There is only one send/receive
    // request thread. We can imitate the user-space version if this is the
    // bottleneck.

    part++;
    data_to_request -= payload_size;

    ice_drain_sendq(nic);

    for (;;) {
      pfa_limit_evict();

      printk("waiting for response\n");

      ice_recv_one(nic);

      struct ethhdr *eth =
          (struct ethhdr*)(recv_header + RMEM_BOGUS_ETH_H_PAD_BYTES);

      if (eth->h_proto != kMemBladeResponseEtherType) {
        memset(recv_header,
               0,
               RMEM_RESPONSE_HEADER_SIZE_BYTES + RMEM_MAX_PAYLOAD_BYTES);
        printk("not what we wanted.\n");

        // Prepare for another receive into the same buffer.
        ice_post_recv(nic, virt_to_phys(recv_header));
        continue;
      }
      
      MemBladeResponseHeader *response = (MemBladeResponseHeader*)(
          recv_header + RMEM_BOGUS_ETH_H_PAD_BYTES + ETH_H_LEN);

      printk("blade response: ver: %02x code: %02x txn: %u part: %u",
             response->common.version, response->common.code,
             response->transaction_id, response->part_id);
      break;
    }
    pfa_limit_evict();
  }

  spin_unlock_irqrestore(&rmem_mut, flags);

  /* Rate limit ourselves to avoid overwhelming the memory blade */
  //pfa_limit_evict();
  //start = pfa_stat_clock();
  //end = pfa_stat_clock();
  /* printk("Started sending at: %lld\n", start); */
  /* printk("Send completions at: %lld\n", end); */

  // Free all headers and all list entries.
  _list_free_all(&send_headers);
  _list_free_all(&recv_headers);
  
  return;
}

static void rmem_remote_set(
    uint8_t *base_vaddr, block_id_t base_block_id, size_t n) {
  size_t i = 0;
  for (; i < n; ++i) {
    uint8_t *src_vaddr = base_vaddr + i * blade->block_size_bytes;
    block_id_t block_id = base_block_id + i;
    printk("rmem_remote_set_one_block i: %u src_vaddr: %x block_id: %lu", i, src_vaddr, block_id);
    rmem_remote_set_one_block(src_vaddr, block_id);
  }
}


static void rmem_remote_get_one_block(
    uint8_t *dst_vaddr, block_id_t block_id) {
  SimpleList send_headers; 
  SimpleList recv_headers; 
  SimpleListNode *next;
  unsigned long flags;
  uint8_t *send_header = NULL;
  uint8_t *recv_header = NULL;
  int num_packets_expected = 0;
  size_t base_offset = 0;
  uint32_t transaction_id = 0;
  uint32_t length = 0;

  // TODO(growly): Hmmmm. Shouldn't this mutex be shared?
  spin_lock_irqsave(&rmem_mut, flags);

  _list_init(&send_headers);
  _list_init(&recv_headers);

  send_header = kcalloc(RMEM_REQUEST_HEADER_SIZE_BYTES, sizeof(uint8_t), 0);

  _list_enqueue(&send_headers, send_header);

  insert_ethernet_header(our_mac,
                         //blade->mac_address,
                         blade_mac,
                         kMemBladeRequestEtherType,
                         send_header + RMEM_BOGUS_ETH_H_PAD_BYTES);

  transaction_id = blade->next_transaction_id++;
  // TODO(growly): What should the part_id be? 0xFF?
  insert_request_header(RMEM_REQUEST_OP_PAGE_READ,
                        RMEM_REQUEST_ALL_PARTS,
                        block_id,
                        transaction_id,
                        send_header + ETH_H_LEN + RMEM_BOGUS_ETH_H_PAD_BYTES);

  // Give the NIC buffers to receive into.
  while (base_offset < blade->block_size_bytes) {
    recv_header = kcalloc(
        RMEM_RESPONSE_HEADER_SIZE_BYTES + RMEM_MAX_PAYLOAD_BYTES,
        sizeof(uint8_t),
        0);

    _list_enqueue(&recv_headers, recv_header);

    ice_post_recv(nic, virt_to_phys(recv_header));
    base_offset += RMEM_MAX_PAYLOAD_BYTES;
    ++num_packets_expected;
  }

  pfa_limit_evict();

  /* printk("rmem_get txid %d, pgid %d\n", txid, pgid); */
  ice_post_send(nic, true, virt_to_phys(send_header),
                RMEM_REQUEST_HEADER_SIZE_BYTES);

  printk("request op: %02x part: %u page: %u txn: %u num_packets_expected %d\n",
         RMEM_REQUEST_OP_PAGE_READ, 0, block_id, transaction_id,
         num_packets_expected);

  ice_drain_sendq(nic);
 
  /* Block until all packets received */
  while (num_packets_expected > 0) {
    // TODO(growly): When to do this?
    pfa_limit_evict();

    ice_recv_one(nic);
    --num_packets_expected;
  }

  // Copy data back to user.
  for (next = recv_headers.front; next != NULL; next = next->next) {
    struct ethhdr *eth =
        (struct ethhdr*)(next->ptr + RMEM_BOGUS_ETH_H_PAD_BYTES);
    printk("header %x received eth type: %04x\n", next->ptr, eth->h_proto);
    
    MemBladeResponseHeader *response = (MemBladeResponseHeader*)(
        next->ptr + RMEM_BOGUS_ETH_H_PAD_BYTES + ETH_H_LEN);

    length = min(
        blade->block_size_bytes - (response->part_id * RMEM_MAX_PAYLOAD_BYTES),
        RMEM_MAX_PAYLOAD_BYTES);
    printk("blade response: ver: %02x code: %02x txn: %u part: %u length: %u",
           response->common.version, response->common.code,
           response->transaction_id, response->part_id, length);

    copy_to_user(dst_vaddr,
                 next->ptr + RMEM_RESPONSE_HEADER_SIZE_BYTES,
                 length);
  }

  spin_unlock_irqrestore(&rmem_mut, flags);

  _list_free_all(&recv_headers);
  _list_free_all(&send_headers);

  return;
}

static void rmem_remote_get(
    uint8_t *base_vaddr, block_id_t base_block_id, size_t n) {
  size_t i = 0;
  for (; i < n; ++i) {
    uint8_t *dst_vaddr = base_vaddr + i * blade->block_size_bytes;
    block_id_t block_id = base_block_id + i;
    rmem_remote_get_one_block(dst_vaddr, block_id);
  }
}

void remote_init(uint8_t *blade_mac,
                 size_t block_size_bytes,
                 size_t num_blocks) {
  int i;
  BUG_ON(blade != NULL || nic != NULL);
  blade = kcalloc(sizeof(MemBladeMetadata), sizeof(uint8_t), 0);
  blade->block_size_bytes = block_size_bytes;
  blade->num_blocks = num_blocks;
  //for (i = 0; i < 6; i++) {
  //  blade->mac_address[i] = blade_mac[i];
  //}
  spin_lock_init(&rmem_mut);
  nic = ice_init();
  printk("Remote memory init complete.\n"
         "\tblock_size_bytes: %u\n"
         "\tnum_blocks: %u\n"
         "\tnic: %p\n",
         blade->block_size_bytes,
         blade->num_blocks,
         nic);
}

void remote_destroy() {
  BUG_ON(blade == NULL);
  kfree(blade);
  blade = NULL;
  nic = NULL;
}

void remote_get(block_id_t src_block_id, void *dst, size_t n) {
  rmem_remote_get(dst, src_block_id, n);
}

void remote_set(void *src, block_id_t dst_block_id, size_t n) {
  rmem_remote_set(src, dst_block_id, n);
}
