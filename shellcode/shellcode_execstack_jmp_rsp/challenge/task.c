#include <stdio.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void gift() {
    __asm__ volatile("jmp rsp\n");
}

void vuln() {
    char buf[32];
    gets(buf);
    puts("cya");
}

int main() {
    setup();
    vuln();
    return 0;
}
