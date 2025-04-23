#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void win(char const* cmd) {
    system(cmd);
}

void free_bubblewrap() {
    __asm__ volatile("pop rbx\n pop rcx\n pop rdx\n pop rax\n push rax\n mov rdi, rsp\n pop rbx\n ret\n");
}

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main() {
    int64_t buf[4];

    setup();

    for (int i = 0; i < 4; ++i) {
        scanf("%ld", &buf[i]);
    }

    *(uintptr_t*)(buf[3] & ~0x7) = (uintptr_t)buf[2];

    puts("cya!");

    return 0;
}
