gcc -masm=intel -fno-stack-protector -Wl,-z,relro,-z,lazy -no-pie -o task ./task.c
