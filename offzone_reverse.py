from pwn import *
import string

for i in string.printables:
    patch = 'mov rax, ' + str(i) + '\nret'
    elf.asm(0x0005555555562F, patch)
    elf.save('./patched')
    os.chmod('./patched', 777)
    p = process('./patched', level='error')
    p.clean()
    p.sendline('n' * 32)
    sleep(0.25)
    res = p.recv()
    print(i, res) 