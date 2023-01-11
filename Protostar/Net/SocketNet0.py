import struct, socket

s = socket.socket()
s.connect(("127.0.0.1", 2999))
data = s.recv(1024)

start = data.find("'") + 1
end = data.find("'", start)
number = int(data[start:end])
LEData = struct.pack("<I", number)

print "server[+]: " + data
print "number[+]: " + str(number)
s.send(LEData)
print "send[+]: " + LEData

OD = s.recv(1024)
print "server[+]: " + OD

s.close()
