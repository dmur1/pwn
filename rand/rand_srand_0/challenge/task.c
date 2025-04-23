#include <stdio.h>
#include <stdlib.h>

void win() {
    system("/bin/sh");
}

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    srand(0);

    for (int i = 0; i < 4; i++) {
        int input;
        scanf("%d%*c", &input);

        int want = rand();
        if (input != want) {
            return;
        }
    }

    win();
}

int main() {
    setup();
    vuln();
    return 0;
}
