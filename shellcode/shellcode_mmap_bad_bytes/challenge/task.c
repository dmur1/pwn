#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

typedef int (*code_t)();

unsigned char bad_chars[] = {'\x0f', '\x6a', '\x3b', '\xd2', '\x56', '\xf6', '\x08'};

int main() {
    unsigned char *buf = (unsigned char*)mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    read(0, buf, 4096);
    for (int i = 0; i < 4096; i++) {
        for (int j = 0; j < sizeof(bad_chars) / sizeof(bad_chars[0]); j++) {
            if (buf[i] == bad_chars[j]) {
                printf("bad byte 0x%x @ 0x%x\n", buf[i], i);
                return 1;
            }
        }
    }
    return ((code_t)buf)();
}
