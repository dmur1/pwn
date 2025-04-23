#include <stdio.h>
#include <unistd.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[256];

    printf("%p\n", setbuf);

    for (int i = 0; i < 3; ++i) {
        read(STDIN_FILENO, buf, sizeof(buf));
        printf(buf);
    }
}

int main() {
    setup();
    vuln();
}
