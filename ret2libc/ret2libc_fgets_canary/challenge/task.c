#include <stdio.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[128];
    printf("%p\n", setbuf);

    fgets(buf, 0x128, stdin);
    printf(buf);

    fgets(buf, 0x128, stdin);
}

int main() {
    setup();
    vuln();
    return 0;
}
