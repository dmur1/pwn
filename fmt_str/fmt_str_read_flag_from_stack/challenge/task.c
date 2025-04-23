#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    int fd = open("./flag.txt", O_RDONLY);
    char flag[16];
    read(fd, flag, sizeof(flag));

    char buff[16];
    scanf("%16s", buff);
    printf(buff);
}

int main() {
    setup();
    vuln();
    return 0;
}
