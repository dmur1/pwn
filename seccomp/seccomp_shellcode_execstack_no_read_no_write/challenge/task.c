#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>

typedef void* scmp_filter_ctx;
typedef int (*code_t)();

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void filter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

void vuln() {
    unsigned char buf[4096];
    read(0, buf, 4096);
    filter();
    ((code_t)buf)();
}

int main() {
    setup();
    vuln();
    return 0;
}
