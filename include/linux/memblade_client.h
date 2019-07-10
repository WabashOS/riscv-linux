#include <linux/types.h>

// Size of remote memory in bytes. This must be <= than the swap device
// (BLK_DEV_RAM in these experiments). BLK_DEV_RAM is calculated a bit
// strangely, it's in KB, and they reserve one page. We just match the final
// available swap size.
#define MEMBLADE_SZ (CONFIG_BLK_DEV_RAM_SIZE*1024 - 4096)

// Size of remote memory (in terms of pages).
// Note this defines the size in emulation mode, but may still be used in
// non-emulation mode (in which it acts as an upper bound on rmem usage)
#define MEMBLADE_NPG (MEMBLADE_SZ / PAGE_SIZE)

// Opcodes
#define MB_OC_PAGE_READ 0
#define MB_OC_PAGE_WRITE 1
#define MB_OC_WORD_READ 2
#define MB_OC_WORD_WRITE 3
#define MB_OC_ATOMIC_ADD 4
#define MB_OC_COMP_SWAP 5

// MMIO addrs
#define MB_BASE       0x10018000L
#define MB_SRC_ADDR   (MB_BASE + 0x00)
#define MB_DST_ADDR   (MB_BASE + 0x08)
#define MB_DSTMAC     (MB_BASE + 0x10)
#define MB_OPCODE     (MB_BASE + 0x16)
#define MB_PAGENO     (MB_BASE + 0x18)
#define MB_REQ        (MB_BASE + 0x20)
#define MB_RESP       (MB_BASE + 0x24)
#define MB_NREQ       (MB_BASE + 0x28)
#define MB_NRESP      (MB_BASE + 0x2C)

/* Send a request to the remote memory blade. This simply sends the request,
 * you must call "mb_wait" to be sure that the request has completed. 
 *
 * src_paddr: physical address to read from (for writes)
 * dst_paddr: physical address to write to (for reads)
 * opcode: Must be one of the MB_OC above
 * pageno: Remote page number to use
 *
 * returns: txid for this request.
 */
int mb_send(uintptr_t src_paddr, uintptr_t dst_paddr,
		int opcode, uint64_t pageno);

/* Wait for the next request to remote memory to complete.
 *
 * Returns: The txid of the most recently completed request.
 */
int mb_wait(void);

/* Initialize the remote memory blade client. You must call this exactly once becore using other mb_* functions.
 */
void mb_init(uint64_t mb_mac);

