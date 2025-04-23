gcc -fno-stack-protector -Wl,-z,relro,-z,now -o task ./task.c
