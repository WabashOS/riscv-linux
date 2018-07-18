This documents the PFA-related changes made to the kernel.

# Page Fault Latency Experiment
This feature is enabled with the PFA\_PFLAT config flag (under PFA options).
You should leave this disabled most of the time since it could affect
performance.

## Usage
The way this works is a multi-step process using the /sys/kernel/mm/pfa\_pflat
sysfs file. You register your process with the pflat system by writing anything
to this file. The kernel then begins recording page evictions. You then need to
trigger some evictions (e.g. by allocating and using memory). You then read
pfa\_pflat to get the virtual address of the most recently evicted page. The
kernel then begins watching for a fault on this address from your process. You
then trigger a fault by accessing the reported page (which should be evicted
now unless you're really unlucky). The kernel records the cycle (rtsc or
rdcycle) in which the page-fault handler starts and will report it the next
time you read pfa\_pflat. If you read the cycle time right before the fault,
you can measure the trap time this way.

## Implementation
Affected Files:
* mm/pfa\_stat.c
* include/linux/pfa\_stat.h
* mm/rmap.c
* arch/riscv/mm/fault.c
* arch/x86/mm/fault.c

The sysfs file is setup along with the rest of pfa\_stat.

The tool is setup like a state machine. The initial state (0) is attempting to
record evictions from the registered task (which is NULL by default). When a
user writes to the sysfs file, we record their task struct * and start really
recording evictions (in try\_to\_unmap\_one). The next read reports the most
recently evicted vaddr and switches to state 1. In state 1, we watch for a 
fault on the provided vaddr. When that triggers we record the cycle and enter
state 0 (so the time only gets recorded once). The user can then read the sysfs
file to get the cycle time and reset the system.
