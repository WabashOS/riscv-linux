#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/byteorder/generic.h>
#include <linux/if_packet.h>
#include <uapi/linux/if_ether.h>
#include <linux/types.h>

#include <linux/rmem_defs.h>
#include <linux/rmem_eth.h>

int _cmp_mac(uint8_t *lhs, uint8_t *rhs) {
  int i;
  for (i = 0; i < ETH_ALEN; ++i) {
    if (lhs[i] < rhs[i]) {
      return -1;
    } else if (lhs[i] > rhs[i]) {
      return 1;
    }
  }
  return 0;
}

// out must be at least 18 bytes long (2 * ETH_ALEN for address, 5 for colons,
// 1 for nul terminator).
void _mac_str(uint8_t *mac, char *out) {
  snprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Insert an ethernet header starting at *buffer; return the length of the
// header. The ethertype is also set to 'ether_type', which is expected to be
// in host byte order when passed to this function.
size_t insert_ethernet_header(uint8_t *source_mac,
                              uint8_t *destination_mac,
                              uint16_t ether_type,
                              char *buffer) {
  int i;
  //assert(sizeof(struct ether_header) == ETH_HLEN);
  struct ethhdr *eth = (struct ethhdr*)buffer;
  memset(eth, 0, ETH_HLEN);
  for (i = 0; i < ETH_ALEN; ++i) {
    eth->h_source[i] = source_mac[i];
  }
  for (i = 0; i < ETH_ALEN; ++i) {
    eth->h_dest[i] = destination_mac[i];
  }
  eth->h_proto = htons(ether_type);
  return ETH_HLEN;
}

size_t append_ethernet_fcs(char *buffer, size_t length) {
  uint32_t *fcs = (uint32_t*)(buffer + length);

  // TODO(growly): Compute FCS in Kernel land (I don't think we use it yet).
  //*fcs = (uint32_t)crc32((uLong)0x0, (const Bytef*)buffer, (uInt)length);

  // Ok so *fcs is in host order and inserting into the packet _without_
  // converting to network order yields the correct FCS (as reported by
  // Wireshark). <linux/crc32.h> mentions that because ethernet sends bytes
  // backwards we actually want to use the reversed crc32 operation (i.e. it's
  // wrapped in bitrev32). TODO(growly): I'm not sure why this works. Maybe
  // because my starting value is wrong too?
  return sizeof(uint32_t);
}

// Creates a request payload for block_id in *buffer; returns the length of the
// packet inserted. The caller must ensure that at least
// sizeof(MemBladeRequestHeader) bytes are available in the buffer following
// the given pointer.
size_t insert_request_header(enum MemBladeRequestOpCode op_code,
                             uint8_t part_id,
                             uint32_t page_number,
                             uint32_t transaction_id,
                             char *buffer) {
  MemBladeRequestHeader *request_header = (MemBladeRequestHeader*)buffer;
  request_header->common.version = PROTOCOL_VERSION;
  request_header->common.code = (uint8_t)op_code;
  request_header->part_id = part_id;
  request_header->page_number = htonl(page_number);
  request_header->transaction_id = htonl(transaction_id);
  return sizeof(MemBladeRequestHeader);
}

size_t insert_response_header(enum MemBladeResponseCode response_code,
                              uint8_t part_id,
                              uint32_t transaction_id,
                              char *buffer) {
  MemBladeResponseHeader *response_header = (MemBladeResponseHeader*)buffer;
  response_header->common.version = PROTOCOL_VERSION;
  response_header->common.code = (uint8_t)response_code;
  response_header->part_id = part_id;
  response_header->transaction_id = htonl(transaction_id);
  return sizeof(MemBladeResponseHeader);
}

