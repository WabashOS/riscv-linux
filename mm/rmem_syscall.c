#include <linux/remote_scratchpad.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/rmem_defs.h>
#include <uapi/asm-generic/errno.h>

// In order to save adding a bajllion syscalls, all rmem operations are
// funnelled through here.
asmlinkage long sys_rmem_op(
     int op, char __user *addr, unsigned long arg0, unsigned long arg1) {
  printk("rmem_syscall dispatching request %d %p %u %u\n", op, addr, arg0, arg1);
  switch ((enum SysRmemOpType)op) {
  case RMEM_SYS_OP_INIT:
    // addr: uint8_t blade_mac[6]
    // arg0: size_t block_size_bytes
    // arg1: size_t num_blocks
    init_remote_memory((uint8_t*)addr, (size_t)arg0, (size_t)arg1);
    break;
  case RMEM_SYS_OP_DESTROY:
    // No args.
    destroy_remote_memory();
    break;
  case RMEM_SYS_OP_SET:
    // addr: void *src
    // arg0: block_id_t dst_block_id
    // arg1: size_t n
    remote_set((void*)addr, (block_id_t)arg0, (size_t)arg1);
    break;
  case RMEM_SYS_OP_GET:
    // addr: void *dst
    // arg0: block_id_t src_block_id
    // arg1: size_t n
    remote_get((block_id_t)arg0, (void*)addr, (size_t)arg1);
    break;
  default:
    return -EINVAL;
  }
  // TODO(growly): Handle errors, user error, poor programming, style.
  return 0;
}
