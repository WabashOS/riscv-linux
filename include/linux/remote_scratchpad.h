#pragma once


// This is the main header to include for remote memory operations and for
// scratchpad use. It is also exposed to user space programs.
// linux/rmem_defs.h defines the structures used in the protocol itself.
// linux/rmem_eth.h defines helper functions for populating the protocol fields.

// TODO(growly): How do other kernel headers allow themselves to be used in
// user applications without conflicting type definitions? Do they omit this
// line or do they guard against its inclusion based on compile time params?
#include <linux/types.h>

typedef uint32_t block_id_t;

// Initialize n block_size-size blocks of remote memory at ethernet address
// 'blade_mac'. Block IDs are then taken from the range [0, num_blocks).
void remote_init(
    uint8_t *blade_mac, size_t block_size_bytes, size_t num_blocks);
void remote_destroy(void);

// The remote memory interface defined by
// https://docs.google.com/document/d/1aTXO8ZXkvyirGcrtxPjf2cqomyVSj6OMbPk14Id2mag

// RDMA.
// TODO(growly): In user space, these should invoke a kernel-side remote memory command.
void remote_get(block_id_t src_block_id, void *dst, size_t n);
void remote_set(void *src, block_id_t dst_block_id, size_t n);

// Scratchpad initialization.
void *scratch_create(size_t size);
void scratch_destroy(void *scratchpad);

// Scratchpad malloc (for convenience).
void *scratch_init(void *scratchpad);
void *scratch_malloc(void *scratchpad, size_t size);
void *scratch_realloc(void *scratchpad, size_t size);
void scratch_free(void *scratchpad, void *ptr);
