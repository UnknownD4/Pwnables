import struct 

print struct.pack("I", 0x1dd8c5e8) + struct.pack("I", 0x01011101)*4
