# Código do experimento

Esta pasta tem tudo o que foi usado para medir o tempo do handshake TLS 1.3
com quatro configurações de troca de chaves, sob diferentes taxas de perda e
atrasos emulados com o tc netem, uma ferramenta do Linux que acrescenta
atraso e perda de pacotes ao tráfego de uma interface de rede. As instruções
para rodar o experimento e conferir os resultados estão no
[README da raiz do repositório](../README.md), e este aqui explica como cada
parte funciona.

## Configurações comparadas

| Configuração | O que o cliente oferece ao servidor |
|---|---|
| X25519 | só o X25519, que é a troca de chaves clássica |
| X25519MLKEM768 | só o grupo híbrido, que combina X25519 e ML-KEM-768 |
| MLKEM768 | só o ML-KEM-768, sem a parte clássica |
| Padrão do OpenSSL | o que o OpenSSL 3.5 envia por padrão, que são as chaves do X25519MLKEM768 e do X25519 juntas |

Cada configuração foi testada com perdas de 0, 1, 5 e 10% e atrasos de 10,
50 e 150 ms em cada sentido, com 100 tentativas por cenário, o que dá 48
cenários e 4800 handshakes.

## Como funciona

O experimento usa três containers Docker, com um roteador entre o cliente e
o servidor.

```
cliente (10.77.1.10) ── roteador ── servidor (10.77.2.10)
                          tc netem: atraso e perda nos dois sentidos
                          tcpdump: grava os pacotes que chegam, antes da perda
```

O roteador fica no meio porque, se a perda fosse aplicada direto no cliente
ou no servidor, a captura só mostraria os pacotes que sobreviveram. Como o
tcpdump grava os pacotes assim que eles chegam ao roteador, antes do netem
decidir se vai descartá-los, os pacotes perdidos também aparecem nas
capturas, e dá para ver cada retransmissão.

Os arquivos desta pasta são os seguintes.

- `Dockerfile` monta a imagem usada pelos três containers, com o Alpine 3.22,
  o OpenSSL 3.5 (que já tem o ML-KEM), o tcpdump, o tshark, o pandas e o
  matplotlib.
- `cliente.c` é o cliente TLS, escrito em C com a libssl. Ele faz todas as
  tentativas de um cenário em sequência, abrindo uma conexão nova a cada uma,
  e mede separadamente o tempo da abertura TCP e o do handshake TLS. Como o
  cronômetro começa logo antes do `connect()`, o tempo de iniciar o programa
  não entra na medida.
- `executar.py` cria as redes e os containers, aplica cada cenário de atraso
  e perda no roteador, liga a captura, roda o cliente e grava as medições.
- `analisar.py` lê as capturas com o tshark, conta os segmentos, os bytes e
  as retransmissões de cada conexão, junta isso com as medições do cliente e
  gera as tabelas e os gráficos do relatório.

## Cuidados para as medidas serem confiáveis

Para que o resultado refletisse o comportamento de uma rede real, o ambiente
foi ajustado em três pontos.

- As otimizações de segmentação das placas virtuais (TSO, GSO e GRO) foram
  desligadas, porque com elas o kernel junta vários segmentos em um pacote
  maior que o MTU, e o netem descartaria todos de uma vez, o que não
  aconteceria em uma rede de verdade.
- O cliente e o servidor usam `net.ipv4.tcp_no_metrics_save=1`, para que o
  kernel não reaproveite o RTT e o temporizador de retransmissão de uma
  conexão na seguinte e cada tentativa comece do zero.
- O servidor não envia session tickets (`-num_tickets 0`) e o cliente não
  guarda sessões, de modo que todo handshake é completo, sem retomada.

## Resultados

Os dados da coleta usada no relatório estão em [resultados/](resultados/),
que tem o seu próprio README explicando cada arquivo. A pasta
`resultados_30rep/` guarda uma primeira coleta, com 30 tentativas por
cenário, que não entrou no relatório porque as estimativas dos casos mais
lentos ficaram instáveis com tão poucas tentativas.
