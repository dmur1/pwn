gcc -fno-stack-protector -masm=intel -no-pie -Wl,-z,relro,-z,now -o task ./task.c
