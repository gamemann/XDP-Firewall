#!/bin/bash

if [ -n "$ROOT" ]; then
    cd $ROOT
fi

llvm-objdump -S --no-show-raw-insn build/xdp/xdp_prog.o > objdump.asm