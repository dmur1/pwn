#!/bin/bash

gcc -fno-stack-protector -Wl,-z,relro,-z,now -no-pie -o task ./task.c
