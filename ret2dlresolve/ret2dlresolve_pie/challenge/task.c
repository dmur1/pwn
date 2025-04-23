#include <stdio.h>
#include <unistd.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void gift() {
    __asm__ volatile("pop rdi\n ret\n pop rsi\n ret\n");
}

void vuln() {
    char buf[32];
    printf("%p\n", setup);
    read(STDIN_FILENO, buf, 320);
}

int main() {
    setup();
    vuln();
}
