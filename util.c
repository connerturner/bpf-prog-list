#include "util.h"
#include <fcntl.h>
#include <string.h>
#include <linux/bpf.h>

void zero_mem(void *attribute, int fill){
    memset(attribute, 0, fill);
}

int fd_valid(int fd){
    return (fcntl(fd, F_GETFD) != -1) ? 1 : 0;
}
