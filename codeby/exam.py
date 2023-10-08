from pwn import *

p = process('/mnt/d/VMs/shared/codeby games/exam')

for i in range(100):
    p.recvuntil(b'Find the volume of a cube with a side of 0x', timeout=5)
    number = int((p.recvuntil(b' ', timeout=1)[:-1:]), 16)
    print(number)
    p.sendline(bytes(number * number * number))

