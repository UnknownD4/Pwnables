#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep\
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt exp.o\
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot\
    -append "console=ttyS0 kaslr nosmap nopti nokaslr quiet kpti=1  panic=1" 
    
    
    
    
    
    
    
    # 
#,+smep,+smap