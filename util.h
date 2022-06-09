#ifndef UTIL_H
#define UTIL_H

#include <fcntl.h>
#include <linux/bpf.h> 

// Zero out a given pointer, bpf functions
// use the same attribute structure so this is
// to clean up any previous calls
void zero_mem(void *attribute, int fill);


// Check if a given file descriptor is valid by getting its fd
// flags, otherwsie fail
int fd_valid(int fd);

// Return mapping of bpf_prog_type in textual form, see linux/bpf.h enum bpf_prog_type
// for latest enums.
extern const char* prog_type_names[32];

#endif
