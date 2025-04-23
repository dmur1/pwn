#include <stdio.h>
#include <stdlib.h>

void win(int a, int b, int c) {
    if (a == 0xabcdabcd && b == 0xfeeffeef && c == 0x12344321) {
        system("/bin/sh");
    }
}

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[32];
    gets(buf);
}

int main() {
    setup();
    vuln();
    return 0;
}
