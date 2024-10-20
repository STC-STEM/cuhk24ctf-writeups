from pwn import *

context.arch = 'amd64'
context.endian = 'little'
context.os = 'linux'
context.terminal = ['konsole', '-e']
context.log_level = 'debug'


tmp_p : process = gdb.debug("./04_chall", gdbscript='''
b *main+53
continue
''', api=True)

tmp_p.gdb.wait()

# x /gx $rbp-0x68
rand_num = int(str(tmp_p.gdb.newest_frame().read_register('rax')), 10)
log.info(f'numeric value: {rand_num}')
log.info(f'hex value: {hex(rand_num)}')
log.info(f'packed value: {p64(rand_num)}')

tmp_p.gdb.quit()

# p : process = gdb.debug("./04_chall", gdbscript='''
# b *main+252
# continue
# ''')
p = remote('chal.24.cuhkctf.org', 24004)
payload = b'cuhk'

def and_bytes(a_bytes, b_bytes):
    return bytes([ a & b for a, b in zip(a_bytes, b_bytes)])

payload = and_bytes(xor(payload, p64(rand_num)[:4]), b'\x7F\x7F\x7F\x7F')

p.sendline(payload)

p.interactive()
