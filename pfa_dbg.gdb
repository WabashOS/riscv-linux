set riscv use_compressed_breakpoint off
set print pretty on
# any panic (including PFA_ASSERT)
b panic
# user segfault
b arch/riscv/mm/fault.c:193
# kernel segfault
b arch/riscv/mm/fault.c:210
# dump pfa log to file named ./log
define dump_log
  dump memory log pfa_log (pfa_log + pfa_log_end)
end

