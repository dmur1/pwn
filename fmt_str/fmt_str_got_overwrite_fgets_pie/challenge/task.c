#include <stdio.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[256];

    printf("%p\n", setbuf);

    for (int i = 0; i < 3; ++i) {
        fgets(buf, sizeof(buf), stdin);
        printf(buf);
    }
}

int main() {
    setup();
    vuln();
}
