from pwn import *

elf = ELF('./vuln')
p = process('./vuln')

system = elf.sumbols['system']