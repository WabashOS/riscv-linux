#pragma once

#include <linux/rmem_defs.h>

int CompareMacAddresses(uint8_t *lhs, uint8_t *rhs);
void MacAddressToString(uint8_t *mac, char *out);

size_t insert_ethernet_header(uint8_t *source_mac,
                              uint8_t *destination_mac,
                              uint16_t ether_type,
                              char *buffer);
size_t append_ethernet_fcs(char *buffer, size_t length);
size_t insert_request_header(enum MemBladeRequestOpCode op_code,
                             uint8_t part_id,
                             uint32_t page_number,
                             uint32_t transaction_id,
                             char *buffer);
size_t insert_response_header(enum MemBladeResponseCode response_code,
                              uint8_t part_id,
                              uint32_t transaction_id,
                              char *buffer);
