BITS 64

mov    rax, 59
mov    rdi, 0x0068732f6e69622f
push   rdi
push   rsp
pop    rsi
xor    rdi, rdi
syscall