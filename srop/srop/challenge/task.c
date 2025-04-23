#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void gift() {
    puts("/bin/sh");
    __asm__ volatile("pop rax\n ret\n");
}

void vuln() {
    __asm__ volatile(
    "mov edi, 0\n"
    "mov rsi, rsp\n"
    "mov edx, 512\n"
    "syscall\n"
    "ret\n");
}

int main() {
    setup();
    vuln();
    return 0;
}
