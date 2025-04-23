#include <stdio.h>

typedef int (*code_t)();

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    unsigned char buf[4096];
    read(0, buf, 4096);
    ((code_t)buf)();
}

int main() {
    setup();
    vuln();
    return 0;
}
