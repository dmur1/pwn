#!/bin/bash

gcc -masm=intel -z execstack -fno-stack-protector -no-pie -o task task.c
