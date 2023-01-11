import struct, socket

res = 0
tlist = [None] * 4
s = socket.socket()
s.connect(("127.0.0.1", 2997))

for x in range(4):
        data = s.recv(1024)
        unpd = struct.unpack("<I", data)[0]
        print "data[+]: " + str(unpd)
        tlist[x] = unpd
        res += tlist[x]

print "list[+]" + str(tlist)
print "result[+]: " + str(res)

sp = struct.pack("<I",res)
print "sp[+]: " + str(sp)
s.send(sp)

