#!/bin/bash

gcc -masm=intel -Wl,-z,relro,-z,now -pie -o task ./task.c

# this is probably brittle but worked locally
# ... you just need to ensure that getrandom uses vdso in the docker on your system
pwninit --bin task --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2
