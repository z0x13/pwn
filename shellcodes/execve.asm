BITS 64

mov rax, 59
mov rdi, 0x68732f2f6e69622f
push 0
push rdi
mov rdi, rsp
mov rsi, 0
mov rdx, 0
syscall
