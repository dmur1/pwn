#!/bin/bash

gcc -z execstack -o task task.c -l seccomp
