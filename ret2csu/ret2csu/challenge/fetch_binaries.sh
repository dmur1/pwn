#!/bin/bash

# `__libc_csu_init` is not present in binaries compiled with glibc 2.34 or newer
# https://lwn.net/Articles/864920/#:~:text=CSU
# therefore we use `FROM debian:bullseye` as this lets us easily work with glibc 2.31.

IMAGE_NAME=`hexdump -n 16 -v -e '/1 "%02x"' /dev/urandom`
CONTAINER_NAME=`hexdump -n 16 -v -e '/1 "%02x"' /dev/urandom`

sudo docker build -t $IMAGE_NAME .
sudo docker run -d --rm --name $CONTAINER_NAME $IMAGE_NAME

echo "allowing task a moment to build..."
sleep 5

sudo docker cp $CONTAINER_NAME:/task ./task
sudo chown $USER:$USER ./task

sudo docker cp --follow-link $CONTAINER_NAME:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
sudo chown $USER:$USER ./libc.so.6

sudo docker cp --follow-link $CONTAINER_NAME:/lib64/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2
sudo chown $USER:$USER ./ld-linux-x86-64.so.2

sudo docker kill $CONTAINER_NAME

/opt/pwninit --bin ./task --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2
rm ./solve.py
