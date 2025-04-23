#!/usr/bin/env python3

import time
import ctypes
from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

libc.srand(0)

for i in range(4):
    p.sendline(str(libc.rand()).encode())

p.interactive()
