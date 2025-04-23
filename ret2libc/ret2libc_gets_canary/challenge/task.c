#include <stdio.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[32];
    printf("%p\n", setbuf);

    gets(buf);
    printf(buf);

    gets(buf);
}

int main() {
    setup();
    vuln();
    return 0;
}
