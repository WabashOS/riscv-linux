#!/bin/bash
LNX=.
find  $LNX                                                                \
    -path "$LNX/arch/*" -prune -o               \
    -path "$LNX/tmp*" -prune -o                                           \
    -path "$LNX/Documentation*" -prune -o                                 \
    -path "$LNX/scripts*" -prune -o                                       \
    -path "$LNX/drivers*" -prune -o                                       \
        -name "*.[chxsS]" -print > cscope.files

# I can't make find exluce /arch/* except /arch/riscv, force it here
find $LNX -path "$LNX/arch/riscv/*" >> cscope.files

cscope -bk
