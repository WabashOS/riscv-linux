#include <asm-generic/unistd.h>

#define __NR_sysriscv  __NR_arch_specific_syscall
#define __NR_pfa  (__NR_arch_specific_syscall + 1)
#ifndef __riscv_atomic
__SYSCALL(__NR_sysriscv, sys_sysriscv)
#endif
__SYSCALL(__NR_pfa, sys_pfa)

#define RISCV_ATOMIC_CMPXCHG    1
#define RISCV_ATOMIC_CMPXCHG64  2
