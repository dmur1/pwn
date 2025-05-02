FROM ubuntu:latest

RUN apt update && apt upgrade -y && apt install -y socat

COPY task_patched .
COPY libc.so.6 .
COPY ld-linux-x86-64.so.2 .

RUN echo "flag{example}" > flag.txt

RUN chmod +x ./task_patched

EXPOSE 9001

CMD ["socat", "tcp-listen:9001,fork,reuseaddr", "exec:./task_patched"]
