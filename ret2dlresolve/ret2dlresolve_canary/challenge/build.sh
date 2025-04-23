gcc -masm=intel -Wl,-z,relro,-z,lazy -no-pie -o task ./task.c
