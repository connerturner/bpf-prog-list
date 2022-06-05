#ifndef UTIL_H
#define UTIL_H

#include <fcntl.h>
#include <linux/bpf.h> 

// Zero out a given pointer, bpf functions
// use the same attribute structure so this is
// to clean up any previous calls
void zero_mem(union bpf_attr *attribute, int fill);


// Check if a given file descriptor is valid by getting its fd
// flags, otherwsie fail
int fd_valid(int fd);

#endif
