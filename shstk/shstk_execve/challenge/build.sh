#!/bin/bash

gcc -z execstack -fno-stack-protector -no-pie -fcf-protection=full -mshstk -o task task.c
