FROM debian:bullseye

RUN apt update && apt upgrade -y && apt install -y gcc socat

COPY task.c .
COPY run.sh .

RUN echo "flag{example}" > flag.txt

RUN chmod +x ./run.sh

EXPOSE 9001

CMD ["./run.sh"]
