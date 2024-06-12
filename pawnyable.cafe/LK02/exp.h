#pragma once

#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

#define DEVICE_PATH "/dev/angus"
#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006
#define ERROR(x) printf("Error: %s\n", x); return -1;


typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;

typedef struct {
  char *ptr;
  size_t len;
} request_t;

int ioctl_init(int fd){
    request_t req = {0};
    if(ioctl(fd, CMD_INIT, &req) < 0){return -1;}
    return 0;
}

int ioctl_setkey(int fd, char *ptr, size_t len){
    request_t req = {0};
    req.len = len; // if (!req.ptr || req.len > 0x1000) return -EINVAL;
    req.ptr = ptr; // if (copy_from_user(ctx->key, req.ptr, req.len)) 
    if(ioctl(fd, CMD_SETKEY, &req) < 0){return -1;}
    return 0;
}

int ioctl_setdata(int fd, char *ptr, size_t len){
    request_t req = {0};
    req.len = len; // if (!req.ptr || req.len > 0x1000) return -EINVAL;
    req.ptr = ptr; // if (copy_from_user(ctx->data, req.ptr, req.len)) 
    if(ioctl(fd, CMD_SETDATA, &req) < 0){return -1;}
    return 0;
}

int ioctl_getdata(int fd, char *ptr, size_t len){
    request_t req = {0};
    req.len = len; // if (!req.ptr || req.len > ctx->datalen) return -EINVAL;
    req.ptr = ptr; // if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL; 
    if(ioctl(fd, CMD_GETDATA, &req) < 0){return -1;}
    return 0;
}

int ioctl_encrypt(int fd){
    request_t req = {0};
    if(ioctl(fd, CMD_ENCRYPT, &req) < 0){return -1;}
    return 0;
}

int ioctl_decrypt(int fd){
    request_t req = {0};
    if(ioctl(fd, CMD_DECRYPT, &req) < 0){return -1;}
    return 0;
}