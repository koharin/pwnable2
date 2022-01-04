#!/usr/bin/python 
from pwn import *

p = process("./challenge")
elf = ELF("./challenge")
libc = elf.libc


