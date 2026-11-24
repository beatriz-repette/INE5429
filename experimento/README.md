# Experimento: TLS 1.3 clássico x pós-quântico em redes degradadas

Mede o tempo do handshake TLS 1.3 com quatro configurações de troca de chaves,
sob diferentes taxas de perda e atrasos emulados com `tc netem`.

| Configuração      | O que o cliente oferece                         |
|-------------------|-------------------------------------------------|
| X25519            | só X25519 (clássico)                            |
| X25519MLKEM768    | só o grupo híbrido                              |
| MLKEM768          | só ML-KEM-768 (pós-quântico puro)               |
| Padrão OpenSSL    | padrão do OpenSSL 3.5: X25519MLKEM768 + X25519  |

Matriz: perdas de 0, 1, 5 e 10% × atrasos de 10, 50 e 150 ms por sentido ×
4 configurações × 100 repetições = 4800 handshakes (cerca de 90 minutos).
A pasta `resultados_30rep/` guarda uma primeira coleta com 30 repetições, que
mostrou estimativas de cauda instáveis e motivou o aumento para 100.

## Como rodar

Precisa só de Docker e Python 3 (sem sudo).

```sh
python3 executar.py --piloto          # teste rápido: 3 handshakes por grupo, sem netem
python3 executar.py --repeticoes 100  # matriz completa (~90 min), grava em resultados/
docker run --rm -u $(id -u):$(id -g) -e MPLCONFIGDIR=/tmp -v "$PWD:/w" -w /w \
    tls-pq-experimento python3 analisar.py resultados
```

## Como funciona

```
cliente (10.77.1.10) ── roteador ── servidor (10.77.2.10)
                         tc netem (atraso + perda nos dois sentidos)
                         tcpdump (pacotes que chegam, antes da perda)
```

- `Dockerfile`: imagem Alpine 3.22 com OpenSSL 3.5 (ML-KEM nativo), tcpdump,
  tshark, pandas e matplotlib.
- `cliente.c`: cliente em C (libssl) que faz N handshakes completos, sem
  retomada de sessão, e mede separadamente o handshake TCP (`tcp_ms`) e o
  TLS (`tls_ms`). O cronômetro começa logo antes do `connect()`, então o
  tempo de iniciar o programa não entra na medida.
- `executar.py`: cria as redes e os containers, aplica cada cenário no
  roteador, captura o tráfego e grava `resultados/medicoes.csv`.
- `analisar.py`: lê as capturas com tshark (segmentos, bytes e
  retransmissões por conexão), junta com as medições e gera
  `resultados/resumo.csv` e os gráficos em `resultados/figuras/`.

Detalhes que garantem medidas corretas:

- TSO/GSO/GRO desligados em todas as interfaces: sem isso, o kernel junta
  segmentos em pacotes maiores que o MTU, e o netem descartaria vários
  segmentos de uma vez.
- `net.ipv4.tcp_no_metrics_save=1` no cliente e no servidor: o kernel não
  reaproveita RTT e RTO de conexões anteriores, então cada tentativa é
  independente.
- O servidor não emite session tickets (`-num_tickets 0`) e o cliente
  desliga o cache de sessão: todo handshake é completo.
- A captura é feita no roteador, nos pacotes que chegam a ele, antes do
  netem. Assim, os pacotes descartados pela "rede" também aparecem no
  `.pcap`, e o tshark consegue identificar as retransmissões.

## Arquivos gerados

- `resultados/ambiente.txt`: versões e configuração usadas.
- `resultados/medicoes.csv`: uma linha por tentativa, como o cliente mediu.
- `resultados/medicoes_com_capturas.csv`: o mesmo, mais segmentos, bytes e
  retransmissões tirados da captura.
- `resultados/resumo.csv`: estatísticas por cenário (média, mediana, desvio
  padrão, p95, taxa de sucesso, % de conexões com retransmissão).
- `resultados/capturas/*.pcap`: um arquivo por cenário (abre no Wireshark).
- `resultados/figuras/`: gráficos em PDF (para o LaTeX) e PNG.
