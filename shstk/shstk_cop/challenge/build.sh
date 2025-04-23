#!/bin/bash

gcc -fno-stack-protector -no-pie -fcf-protection=full -mshstk -o task task.c
