#include <stdio.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    unsigned char buf[256];
    printf("%p\n", setup);
    gets(buf);
}

int main() {
    setup();
    vuln();
    return 0;
}
