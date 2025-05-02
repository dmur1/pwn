#!/bin/bash

gcc -masm=intel -Wl,-z,relro,-z,now -pie -o task ./task.c
