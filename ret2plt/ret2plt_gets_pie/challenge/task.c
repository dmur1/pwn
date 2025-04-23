#include <stdio.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void gift() {
    __asm__ volatile("pop rdi\n ret\n");
}

void vuln() {
    char buf[32];
    puts("you might need this");
    printf("%p\n", gift);
    gets(buf);
}

int main() {
    setup();
    vuln();
    return 0;
}
