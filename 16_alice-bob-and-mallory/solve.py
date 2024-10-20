from pwn import *

context.arch = 'amd64'
context.endian = 'little'
context.os = 'linux'
context.terminal = ['konsole', '-e']
context.log_level = 'debug'

# p = process('./chall')
p = remote('chal.24.cuhkctf.org', 24016)

payloads = None
with open('./payloads.txt') as f:
    payloads = f.readlines()

for i in range(100):
    p.sendafter(b'(0 <= N <= 10^16)!\n', payloads[i].encode())

p.interactive()
