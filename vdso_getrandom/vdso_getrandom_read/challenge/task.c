#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

// https://github.com/torvalds/linux/blob/c1336865c4c90fcc649df0435a7c86c30030a723/include/vdso/getrandom.h#L33

#define CHACHA_KEY_SIZE 32
#define CHACHA_BLOCK_SIZE 64

struct vgetrandom_state {
    union {
        struct {
            uint8_t batch[CHACHA_BLOCK_SIZE * 3 / 2];
            uint32_t key[CHACHA_KEY_SIZE / sizeof(uint32_t)];
        };
        uint8_t batch_key[CHACHA_BLOCK_SIZE * 2];
    };
    uint64_t generation;
    uint8_t pos;
    bool in_use;
};

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

struct vgetrandom_state *get_state_tls() {
    __asm__ volatile(
        "mov r14, qword ptr fs:[0x10]\n"
        "mov rax, qword ptr [r14 + 0x918]\n" // glibc dependent tls offset
    );
}

void vuln() {
    uint8_t b[16];
    getrandom(b, 16, GRND_RANDOM);

    struct vgetrandom_state* state = get_state_tls();
    write(STDOUT_FILENO, state, sizeof(struct vgetrandom_state));

    getrandom(b, 16, GRND_RANDOM);

    uint8_t r[16];
    read(STDIN_FILENO, r, 16);

    if (memcmp(b, r, 16) != 0) {
        exit(0);
    }

    system("/bin/sh");
}

int main() {
    setup();
    vuln();
    return 0;
}
