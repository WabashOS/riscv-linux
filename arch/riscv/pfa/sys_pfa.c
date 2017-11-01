
#include<linux/syscalls.h>
#include<asm/unistd.h>

#include<linux/sched.h>
#include<linux/pfa.h>

/* Generic PFA syscall, used for all sorts of communication 
 * Right now it will manually evict the page at "address" 
 *
 * passing NULL for vaddr will drain the newpage queue
 */
SYSCALL_DEFINE0(pfa)
{
#ifndef USE_PFA
  printk("pfa syscall: PFA not enabled, doing nothing.\n");
#else
  pfa_set_tsk(current);
#endif

  return 1;
}
