# Imagem única usada pelo cliente, pelo roteador, pelo servidor e pela análise.
# Alpine 3.22 traz o OpenSSL 3.5, que já tem ML-KEM nativo.
FROM alpine:3.22
RUN apk add --no-cache openssl openssl-dev build-base iproute2 iproute2-tc \
        ethtool tcpdump tshark python3 py3-pandas py3-matplotlib
COPY cliente.c /opt/cliente.c
RUN gcc -O2 -Wall -o /usr/local/bin/cliente-tls /opt/cliente.c -lssl -lcrypto
