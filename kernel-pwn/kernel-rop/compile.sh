gcc smepAndKpti.c -o initramfs/exp -static
chmod a+x initramfs/exp 
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../