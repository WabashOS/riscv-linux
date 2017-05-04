#ifndef _PFA_HELPER_H
#define _PFA_HELPER_H

extern pid_t pfa_pid;
extern unsigned long pfa_addr;

#define IS_PFA_ADDR(PFA_ADDRESS) (pfa_pid == task_tgid_vnr(current) && \
      pfa_addr == (PFA_ADDRESS & (~0 << PAGE_SHIFT)))

static inline uint64_t get_cycle(void)
{
  register unsigned long __v;
  __asm__ __volatile__ ("rdcycle %0" : "=r" (__v));
  return __v;
}

#endif
