#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/bpf.h>

#define SYSBPF 321

int bpf_prog_sys(union bpf_attr *attr, unsigned int attrsize){
    // Default x86_64 SYSCALL table the SYS_bpf is call NR 321
    // use the preprocessor for easy adaptation to different arch.
    int callno = SYSBPF;
    // sys_bpf syscall with the get next ID command. See man 2 bpf for details.
    return syscall(callno, BPF_PROG_GET_NEXT_ID,  attr, attrsize) ? errno: 0;
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
            printf("%u\t\n",curr_id);
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
    if(geteuid() == 0)
        return iterate_bpf_progs();
    
    // Else fail with EACCES error and print a perror to stderror
    errno = EACCES;
    perror("Operation not permitted");
    exit(1);
}
