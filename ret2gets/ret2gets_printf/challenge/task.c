#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char* gets(char*);

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void gift() {
    char buf[32];
    read(STDIN_FILENO, buf, 132);
}

void vuln() {
    char buf[32];
    gets(buf);
    printf("%d\n", strlen(buf));
}

int main() {
    setup();
    vuln();
}
