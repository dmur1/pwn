#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <unistd.h>

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

void gift() {
    __asm__ volatile("pop rax\nret\n");
    __asm__ volatile("pop rdi\nret\n");
    __asm__ volatile("pop rsi\nret\n");
    __asm__ volatile("pop rdx\nret\n");
    __asm__ volatile("syscall\nret\n");
    __asm__ volatile("mov qword ptr[rdi], rsi\nret\n");
}

void vuln() {
    char buf[32];
    printf("%p\n", setup);

    gets(buf);
    printf(buf);

    gets(buf);

    filter();
}

int main() {
    setup();
    vuln();
    return 0;
}
