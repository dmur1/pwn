#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char* gets(char*);
typedef void (*func_t)(char*);

typedef struct widget {
    char name[32];
    func_t func;
} widget;

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win() {
    system("/bin/sh");
}

void say_my_name(char* name) {
    puts(name);
}

void vuln() {
    widget w;
    w.func = say_my_name;
    gets(w.name);
    w.func(w.name);
}

int main() {
    setup();
    vuln();
    return 0;
}
