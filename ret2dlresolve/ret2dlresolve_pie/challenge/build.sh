gcc -masm=intel -fno-stack-protector -Wl,-z,relro,-z,lazy -o task ./task.c
