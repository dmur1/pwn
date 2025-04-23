#!/bin/bash

gcc -masm=intel -fno-stack-protector -no-pie -o task ./task.c
