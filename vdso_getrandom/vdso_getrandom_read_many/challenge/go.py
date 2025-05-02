#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task_patched", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

def rotl(v, s):
    return ((v << s) | (v >> (32 - s))) & 0xffffffff

def chacha_state(key, counter, nonce):
    state = [0] * 16
    state[ 0] = struct.unpack("<I", b"expa")[0]
    state[ 1] = struct.unpack("<I", b"nd 3")[0]
    state[ 2] = struct.unpack("<I", b"2-by")[0]
    state[ 3] = struct.unpack("<I", b"te k")[0]
    state[ 4] = struct.unpack("<I", key[0:4])[0]
    state[ 5] = struct.unpack("<I", key[4:8])[0]
    state[ 6] = struct.unpack("<I", key[8:12])[0]
    state[ 7] = struct.unpack("<I", key[12:16])[0]
    state[ 8] = struct.unpack("<I", key[16:20])[0]
    state[ 9] = struct.unpack("<I", key[20:24])[0]
    state[10] = struct.unpack("<I", key[24:28])[0]
    state[11] = struct.unpack("<I", key[28:32])[0]
    state[12] = counter & 0xffffffff
    state[13] = struct.unpack("<I", nonce[0:4])[0]
    state[14] = struct.unpack("<I", nonce[4:8])[0]
    state[15] = struct.unpack("<I", nonce[8:12])[0]
    return state

def chacha20_quater_round(a, b, c, d):
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl(d, 16)
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl(b, 12)
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl(d, 8)
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl(b, 7)
    return a, b, c, d

def chacha20_block(state):
    x = [0] * 16
    for i in range(16):
        x[i] = state[i]

    for i in range(10):
        x[ 0], x[ 4], x[ 8], x[12] = chacha20_quater_round(x[ 0], x[ 4], x[ 8], x[12])
        x[ 1], x[ 5], x[ 9], x[13] = chacha20_quater_round(x[ 1], x[ 5], x[ 9], x[13])
        x[ 2], x[ 6], x[10], x[14] = chacha20_quater_round(x[ 2], x[ 6], x[10], x[14])
        x[ 3], x[ 7], x[11], x[15] = chacha20_quater_round(x[ 3], x[ 7], x[11], x[15])
        x[ 0], x[ 5], x[10], x[15] = chacha20_quater_round(x[ 0], x[ 5], x[10], x[15])
        x[ 1], x[ 6], x[11], x[12] = chacha20_quater_round(x[ 1], x[ 6], x[11], x[12])
        x[ 2], x[ 7], x[ 8], x[13] = chacha20_quater_round(x[ 2], x[ 7], x[ 8], x[13])
        x[ 3], x[ 4], x[ 9], x[14] = chacha20_quater_round(x[ 3], x[ 4], x[ 9], x[14])

    for i in range(16):
        x[i] = (x[i] + state[i]) & 0xffffffff
    return x

batch = p.recv(128)
p.recv(16) # we don't really care about the rest of the structure here

# first use the rest of the batch...
p.send(batch[16:32])
p.send(batch[32:48])
p.send(batch[48:64])
p.send(batch[64:80])
p.send(batch[80:96])

for x in range(10):
    # the batch_key is the last 32 bytes of the batch
    batch_key = batch[-32:]

    # we generate two blocks both with nonce=0
    # ... the first block counter=0
    state = chacha_state(key=batch_key, counter=0, nonce=b"\x00" * 12)
    state = chacha20_block(state)

    batch = b""
    for i in range(16):
        batch += struct.pack("<I", state[i])

    # ... the second block counter = 1
    state = chacha_state(key=batch_key, counter=1, nonce=b"\x00" * 12)
    state = chacha20_block(state)

    for i in range(16):
        batch += struct.pack("<I", state[i])

    p.send(batch[0:16])
    p.send(batch[16:32])
    p.send(batch[32:48])
    p.send(batch[48:64])
    p.send(batch[64:80])
    p.send(batch[80:96])

p.interactive()
