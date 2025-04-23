#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

typedef int (*code_t)();

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    unsigned char *buf = (unsigned char*)mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    read(0, buf, 4096);
    ((code_t)buf)();
}

int main() {
    setup();
    vuln();
    return 0;
}
