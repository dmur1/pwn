#include <stdio.h>
#include <stdlib.h>

char* gets(char*);

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[32];
    gets(buf);
    puts(buf);
}

int main() {
    setup();
    vuln();
}
