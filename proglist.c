#include "util.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdlib.h>

#define SYSBPF 321

int bpf_prog_sys(union bpf_attr *attr, unsigned int attrsize){
    // Default x86_64 SYSCALL table the SYS_bpf is call NR 321
    // use the preprocessor for easy adaptation to different arch.
    int callno = SYSBPF;
    // sys_bpf syscall with the get next ID command. See man 2 bpf for details.
    return syscall(callno, BPF_PROG_GET_NEXT_ID,  attr, attrsize) ? errno: 0;
}

int bpf_prog_fd(__u32 prog_id){
    int callno = SYSBPF;
    union bpf_attr fd_attr = {
        .prog_id = prog_id
    };
    int fd = syscall(callno, BPF_PROG_GET_FD_BY_ID, &fd_attr, sizeof(fd_attr));
    return fd_valid(fd) ? fd : 0;
} 

int iterate_bpf_progs() {
    // bpf(2) requires an attribute struct to pass parameters to the syscall
    union bpf_attr prog_attr = {
        //start at attribute 0 and go until error.
        .start_id = 0
    };
    //tabulate output
    printf("id\tfd\t\n");
    while(1) {
        int idcall = bpf_prog_sys(&prog_attr, sizeof(prog_attr));
        if(!idcall) {
            __u32 curr_id = prog_attr.next_id;
            printf("%u\t",curr_id);
            // Retrieve fd from id
            int fdcall = bpf_prog_fd(curr_id);
            if(fdcall != 0) {
                // only then prepare a prog_info sruct
                printf("%u\t",fdcall);
            }
            printf("\n");
            // PROG_GET_NEXT_ID checks for next program > start_id
            // so set start_id to the already printed program id and loop.
            prog_attr.start_id = prog_attr.next_id;
        } else {
            break;
        }
    }

    return 0;
}

int main(void) {

    // Effective uid needs to be a superuser to access the syscall
    if(geteuid() == 0){
        return iterate_bpf_progs();
    } else {
        // Else fail with EACCES error and print a perror to stderror
        errno = EACCES;
        perror("Operation not permitted");
        exit(1);
    }
}
