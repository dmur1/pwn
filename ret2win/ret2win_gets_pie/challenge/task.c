#include <stdio.h>
#include <stdlib.h>

void win() {
    system("/bin/sh");
}

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[4];
    printf("%p\n", setup);
    gets(buf);
}

int main() {
    setup();
    vuln();
    return 0;
}
