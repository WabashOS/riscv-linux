#pragma once

#include <linux/rmem_defs.h>
#include <linux/rmem_eth.h>
#include <linux/rmem_defs.h>

#define DEFAULT_INTERFACE_NAME "ens33"

// icenet_raw requires 64-bit aligned data. We pad the ethernet header with a
// bogus 2 bytes just because.
//
// Header should be ETH_H_LEN + 2 + sizeof(MemBladeRequestHeader)
//                     14     + 2 +               12               = 28 bytes
#define ETH_H_LEN 14
#define RMEM_REQUEST_HEADER_SIZE_BYTES 28
#define RMEM_RESPONSE_HEADER_SIZE_BYTES 24
#define RMEM_BOGUS_ETH_H_PAD_BYTES 2

//struct _HashTable;

// TODO(growly): Use kernel code style.

typedef struct {
  //pthread_mutex_t lock;

  // Structure to track outstanding requests.
  // struct _HashTable *request_table;

  uint32_t next_transaction_id;

  // Expected resource availability for quick sanity checks.
  size_t block_size_bytes;
  size_t num_blocks;
  uint8_t mac_address[6];
} MemBladeMetadata;

typedef struct _SimpleListNode {
  void *ptr;
  struct _SimpleListNode *next; 
} SimpleListNode;

typedef struct {
  SimpleListNode *front;
  SimpleListNode *back;
} SimpleList;

// TODO(growly): Import MemBladeRequestMetadata if needed.

// Handle to the (single global) blade.
extern MemBladeMetadata *blade;
