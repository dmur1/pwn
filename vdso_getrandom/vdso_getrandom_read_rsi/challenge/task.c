#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    uint8_t a[32];
    uint8_t b[32];

    fgets(a, sizeof(a), stdin);
    getrandom(b, 32, GRND_RANDOM);
    printf(a);

    uint8_t c[32];
    read(STDIN_FILENO, c, 32);
    getrandom(b, 32, GRND_RANDOM);
    if (memcmp(b, c, 32) != 0) {
        exit(0);
    }

    system("/bin/sh");
}

int main() {
    setup();
    vuln();
    return 0;
}
