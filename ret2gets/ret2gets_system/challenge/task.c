#include <stdio.h>
#include <stdlib.h>

char* gets(char*);

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
    gets(buf);
}

int main() {
    setup();
    vuln();
}
