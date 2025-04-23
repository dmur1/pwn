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
    char buf[32];
    printf("%p\n", setup);

    gets(buf);
    printf(buf);

    gets(buf);
}

int main() {
    setup();
    vuln();
    return 0;
}
