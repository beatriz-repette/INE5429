# Mini-exemplo

Estes são os scripts usados no mini-exemplo da Seção 2.5 do relatório, que
gerou a tabela com o tamanho das mensagens e a figura do Wireshark. Eles
capturam um único handshake TLS 1.3 de cada configuração, sem atraso nem
perda, entre dois containers com o OpenSSL 3.5, para mostrar em quantos
segmentos TCP o ClientHello e a resposta do servidor são divididos.

Para repetir, basta ter Docker e rodar o script abaixo.

```sh
./captura/capturar.sh
```

- `Dockerfile` monta uma imagem com o OpenSSL 3.5, o tcpdump, o ethtool e o
  tshark.
- `capturar.sh` sobe o servidor, faz um handshake com cada configuração,
  grava as capturas em `capturas/` e mostra as medidas de cada uma.
- `analisar.sh` lê uma captura e mostra o tamanho do ClientHello, do
  ServerHello e das chaves de cada lado, além de quantos segmentos cada
  mensagem ocupou.
- `capturas/` tem as capturas usadas no relatório. Como aqui os pacotes
  foram gravados inteiros, o Wireshark consegue remontar as mensagens, e o
  filtro `tls.handshake.type == 1` mostra o ClientHello completo.
