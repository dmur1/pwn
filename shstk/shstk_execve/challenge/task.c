#include <stdio.h>
#include <unistd.h>

char* gets(char* s);

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int menu() {
    puts("1) gets");
    puts("2) execve");

    printf("enter choice: ");

    int choice;
    scanf("%d", &choice);
    getchar();

    return choice;
}

void vuln() {
    switch (menu()) {
        case 1:
            unsigned char buf[256];
            gets(buf);
            break;
        case 2:
            execve("task", 0, 0);
            break;
    }
}

int main() {
    setup();
    vuln();
    return 0;
}
