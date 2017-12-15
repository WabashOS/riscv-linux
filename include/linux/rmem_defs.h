#pragma once

#include <linux/types.h>

#define PROTOCOL_VERSION 0x00

#define RMEM_REQUEST_ALL_PARTS 0x00
#define RMEM_MAX_PAYLOAD_BYTES 1368

// The ethertype of the memory blade protocol.
// NOTE(growly): If ethertype is > 1536, it is interpreted as a protocol
// number. If not, it is interpreted as the ethernet payload.
static const uint16_t kMemBladeRequestEtherType = 0x0804;
static const uint16_t kMemBladeResponseEtherType = 0x0805;

// Syscall op code.
enum SysRmemOpType {
  RMEM_SYS_OP_INIT = 0,
  RMEM_SYS_OP_DESTROY = 1,
  RMEM_SYS_OP_SET = 2,
  RMEM_SYS_OP_GET = 3,
};

enum MemBladeRequestOpCode {
  RMEM_REQUEST_OP_PAGE_READ = 0,
  RMEM_REQUEST_OP_PAGE_WRITE = 1,
  // The following require the MemBladeOpArgs payload, below.
  RMEM_REQUEST_OP_WORD_READ = 2,
  RMEM_REQUEST_OP_WORD_WRITE = 3,
  RMEM_REQUEST_OP_ATOMIC_ADD = 4,
  RMEM_REQUEST_OP_ATOMIC_COMPARE_SWAP = 5
};

enum MemBladeResponseCode {
  RMEM_RESPONSE_SUCCESS_WITH_DATA = 0,
  RMEM_RESPONSE_SUCCESS_NO_DATA = 1,
  RMEM_RESPONSE_FAILURE = 2	// And anything higher.
};

typedef struct {
  uint8_t version;
  uint8_t code;   // op_code or response_code depending on request/response.
} MemBladeCommonHeader;

typedef struct {
  MemBladeCommonHeader common;
  uint8_t part_id;  // 0xFF = send all parts.
  uint8_t reserved;
  // TODO(growly): This was actually 8 bytes, not 32, to get it to 8-byte
  // alignment. Make sure this is reflected everywhere.
  uint64_t page_number; // This is the block ID in network byte order.
  uint32_t transaction_id;  // Network byte order.
} __attribute__((packed)) MemBladeRequestHeader;

typedef struct {
  uint16_t offset_disable_size;
  uint8_t reserved[6];
  uint64_t arg0;
  uint64_t arg1;
} __attribute__((packed)) MemBladeOpArgs;

typedef struct {
  MemBladeCommonHeader common;
  uint8_t part_id;
  uint8_t reserved;
  uint32_t transaction_id;  // Network byte order.
} __attribute__((packed)) MemBladeResponseHeader;

