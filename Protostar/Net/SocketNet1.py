import socket, struct

s = socket.socket()
s.connect(("127.0.0.1", 2998))

data = s.recv(1024)
unpd = str(struct.unpack("<I", data)[0])
print "data: " + unpd
s.send(unpd)
print(s.recv(1024))

s.close()

