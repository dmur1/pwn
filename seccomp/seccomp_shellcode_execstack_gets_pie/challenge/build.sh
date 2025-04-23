#!/bin/bash

gcc -z execstack -fno-stack-protector -o task task.c -l seccomp
