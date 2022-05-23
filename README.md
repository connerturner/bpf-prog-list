bpf-prog-list. List bpf programs on system.

### Why not bpftool?
Well this is a small binary and does what I need, also a good learning exercise.

### A note on Architecture
By default this targets x86_64 since a bare `syscall()` is used the NR for
SYS_bpf may be different on your machine.

It can be checked by inspecting the preprocessor stage of your compiler by printing
the macro defined in `sys/syscall.h`:

```
    printf SYS_bpf | gcc -include sys/syscall.h -E -
```

for clang just swap out gcc command.

