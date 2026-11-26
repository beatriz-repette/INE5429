# Mini-exemplo: o ClientHello em cada configuração

Scripts usados no mini-exemplo da Seção 2.5 do relatório (Tabela da captura e
figura do Wireshark). Eles capturam um único handshake TLS 1.3 por
configuração, sem atraso nem perda, entre dois containers com OpenSSL 3.5.

```sh
cd captura
./capturar.sh
```

- `Dockerfile`: imagem Alpine 3.22 com OpenSSL 3.5, tcpdump, ethtool e tshark.
- `capturar.sh`: sobe o servidor, faz um handshake com cada configuração
  (X25519, X25519MLKEM768, MLKEM768 e padrão do OpenSSL), grava
  `capturas/<configuração>.pcap` e imprime as medidas.
- `analisar.sh`: lê um `.pcap` e imprime o tamanho do ClientHello, dos
  key_shares, do ServerHello e quantos segmentos TCP cada mensagem ocupou.
- `capturas/`: as capturas usadas no relatório (abrem no Wireshark). Aqui a
  captura guarda os pacotes inteiros, então o filtro `tls.handshake.type == 1`
  mostra o ClientHello já remontado.
