#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>

typedef void* scmp_filter_ctx;

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void filter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

void vuln() {
    unsigned char buf[256];
    printf("%p\n", setup);
    gets(buf);
}

int main() {
    setup();
    filter();
    vuln();
    return 0;
}
