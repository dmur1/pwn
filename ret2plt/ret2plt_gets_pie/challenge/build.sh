gcc -fno-stack-protector -masm=intel -Wl,-z,relro,-z,now -o task ./task.c
