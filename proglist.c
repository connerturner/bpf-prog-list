#include "util.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
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


int get_prog_info(int fd, struct bpf_prog_info *prog, long *prog_length){
    int callno = SYSBPF;
    union bpf_attr prog_attr = {
        .info.bpf_fd = fd,
        .info.info_len = *prog_length,
        .info.info = (__u64)((uintptr_t)prog)
    };
    //zero_mem(&program, sizeof(program));
    
    int progerr = syscall(callno, BPF_OBJ_GET_INFO_BY_FD, &prog_attr, sizeof(prog_attr));
    // return the syscall error on fail or the program attribute struct length
    return !progerr ? prog_attr.info.info_len : progerr;
}

void print_prog_info(int fd) {
    if(fd_valid(fd)){
        struct bpf_prog_info program = {};
        long program_length = sizeof(program);
        int prog_struct_size = get_prog_info(fd, &program, &program_length);
        
        if (prog_struct_size > 0) {
            program_length = prog_struct_size;

            printf("%u\t %s\t %x\t+%llus\t%lld\t", program.id, prog_type_names[program.type], program.gpl_compatible, (program.load_time / 1000000000LL), program.run_time_ns);

        } else {
            printf("Program struct size invalid. Err: %u", prog_struct_size);
        }

    } else {
        printf("FD Not Available, Can't show prog info \n");
    }
}

int iterate_bpf_progs() {
    // bpf(2) requires an attribute struct to pass parameters to the syscall
    union bpf_attr prog_attr = {
        //start at attribute 0 and go until error.
        .start_id = 0
    };
    //tabulate output
    printf("id\ttype\tgpl\tload_time\trun_time\t\n");
    while(1) {
        int idcall = bpf_prog_sys(&prog_attr, sizeof(prog_attr));
        if(!idcall) {
            __u32 curr_id = prog_attr.next_id;
            int fdcall = bpf_prog_fd(curr_id);
            if(fdcall != 0) {
                // only then prepare a prog_info sruct
                print_prog_info(fdcall);
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
