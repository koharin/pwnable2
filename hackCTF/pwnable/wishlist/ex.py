#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./wishlist")
elf = ELF("./wishlist")
libc = elf.libc 

def make_wish(data):
    p.sendafter("input: ", '1')
    p.sendafter("wishlist: ", data)

def view_wish(index):
    p.sendafter("input: ", '2')
    p.sendafter("index: ", str(index))

def remove_wish(index):
    p.sendafter("input: ", '3')
    p.sendafter("index: ", str(index))

make_wish("AAAAAAAA")
make_wish('B'*8)



p.interactive()
