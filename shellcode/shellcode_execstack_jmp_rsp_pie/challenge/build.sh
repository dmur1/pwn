#!/bin/bash

gcc -masm=intel -z execstack -fno-stack-protector -o task task.c
