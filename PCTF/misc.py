from pwn import *

context.log_level = 'error'

FLAG = b'pctf{'
for i in range(6, 19):
    for j in range(33, 127):
        tmp = FLAG
        tmp += j.to_bytes(1, byteorder='little')
        tmp = tmp.ljust(19, b'0')

        r = remote('chal.pctf.competitivecyber.club', 4757)
        r.recvuntil(b'What is the password: ')
        r.sendline(tmp)

        counter = 0
        res = r.recvline()
        while b'error' not in res:
            res = r.recvline()
            counter += 1

        r.close()

        if int(counter / 2) == i:
            FLAG = tmp[:i]
            break

print(FLAG + b'}')