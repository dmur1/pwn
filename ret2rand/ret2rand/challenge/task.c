#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win(char const* s) {
    system(s);
}

void vuln() {
    char buf[32];
    sprintf(buf, "%d", rand());
    puts(buf);
    read(STDIN_FILENO, buf, 132);
}

int main() {
    setup();
    vuln();
}
