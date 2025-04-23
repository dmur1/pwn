#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// the order is important to ensure (main&(~0xff)) == (win&(~0xff))

int main() {
    setup();
    vuln();
    return 0;
}

void win() {
    system("/bin/sh");
}

void vuln() {
    char buf[32];

    read(0, buf, 57);
    printf(buf);

    read(0, buf, 57);
}

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
