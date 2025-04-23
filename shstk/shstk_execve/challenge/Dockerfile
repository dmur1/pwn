FROM ubuntu:latest

RUN apt-get update && apt-get upgrade -y && apt-get install -y socat

COPY task .

RUN echo "flag{example}" > flag.txt

RUN chmod +x ./task

EXPOSE 9001

ENV GLIBC_TUNABLES=glibc.cpu.x86_shstk=on:glibc.cpu.x86_ibt=on

CMD ["socat", "tcp-listen:9001,fork,reuseaddr", "exec:./task"]
