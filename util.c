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

const char* prog_type_names[32] = {
    "UNSPEC",
	"SOCKET_FILTER",
	"KPROBE",
	"SCHED_CLS",
	"SCHED_ACT",
	"TRACEPOINT",
	"XDP",
    "PERF_EVENT",
	"CGROUP_SKB",
	"CGROUP_SOCK",
	"LWT_IN",
	"LWT_OUT",
	"LWT_XMIT",
	"SOCK_OPS",
	"SK_SKB",
	"CGROUP_DEVICE",
	"SK_MSG",
	"RAW_TRACEPOINT",
	"CGROUP_SOCK_ADDR",
	"LWT_SEG6LOCAL",
	"LIRC_MODE2",
	"SK_REUSEPORT",
	"FLOW_DISSECTOR",
	"CGROUP_SYSCTL",
	"RAW_TRACEPOINT_WRITABLE",
	"CGROUP_SOCKOPT",
	"TRACING",
	"STRUCT_OPS",
	"EXT",
	"LSM",
	"SK_LOOKUP",
	"SYSCALL",
};
