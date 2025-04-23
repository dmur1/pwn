FROM ubuntu:latest

RUN apt update && apt upgrade -y && apt install -y socat

COPY task .

RUN echo "flag{example}" > flag.txt

RUN chmod +x ./task

EXPOSE 9001

CMD ["socat", "tcp-listen:9001,fork,reuseaddr", "exec:./task"]
