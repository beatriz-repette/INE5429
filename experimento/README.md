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

## Preparação

Em Linux com Python 3 e acesso ao serviço Docker, abra o diretório do experimento.
O Docker compila a imagem com OpenSSL, o cliente e as ferramentas de análise.

```sh
git clone https://github.com/beatriz-repette/INE5429.git
cd INE5429/experimento
docker info
docker build -t tls-pq-experimento .
```

## Reproduzir as estatísticas usando os dados existentes

A coleta de 24/11/2026 está no commit `2937eab`. A partir de `experimento/`,
copie apenas as entradas para uma pasta de trabalho. A análise usa as 48
capturas e as durações medidas pelo cliente. Os resultados de referência ficam
preservados em `resultados/`.

```sh
analise=$(mktemp -d -p "$PWD" reanalise.XXXXXX)
cp -r resultados/capturas resultados/medicoes.csv "$analise/"
docker run --rm -u $(id -u):$(id -g) -e MPLCONFIGDIR=/tmp -v "$PWD:/w" -w /w \
    tls-pq-experimento python3 analisar.py "$(basename "$analise")"
```

Em um ambiente com tshark, pandas e matplotlib instalados, o último comando
também pode ser substituído por `python3 analisar.py "$analise"`. Para conferir
o resultado, compare `resumo.csv` e `lentos_por_perda.csv` com as tabelas do PDF.
A matriz tem 48 linhas de resumo e 4.799 conexões concluídas em 4.800 tentativas.
Na linha do padrão OpenSSL com 10% de perda, devem aparecer 126 conexões lentas
em 300 e 286,74 ms na coluna `extra_medio_ms`. Essa coluna usa apenas os
handshakes concluídos. Para o caso de erro, abra `MLKEM768_p5_a150.pcap` no
Wireshark e aplique o filtro `tcp.port == 47956`.

## Testar a coleta ou fazer uma nova medição

O piloto testa as quatro configurações, com três tentativas por configuração e
sem atraso ou perda adicionais. Use uma pasta nova para cada execução.

```sh
python3 executar.py --piloto --saida piloto-local
```

O resultado esperado é uma linha `3/3 ok` para cada configuração, quatro
arquivos em `piloto-local/capturas/` e 12 medições em `piloto-local/medicoes.csv`.
Para uma nova matriz completa, execute:

```sh
python3 executar.py --repeticoes 100 --saida coleta-local
```

O padrão sem `--repeticoes` é 30. Sem `--saida`, uma nova matriz grava em
`resultados/` e pode sobrescrever a coleta publicada. Os tempos e as contagens
de perdas variam entre coletas. Para analisar uma nova matriz, passe a pasta
da coleta completa para `analisar.py`. O piloto serve para verificar o ambiente.

## Compilar o relatório

Com uma distribuição LaTeX que inclua pdfLaTeX, latexmk, TikZ, lmodern e
suporte ao português, execute a partir de `experimento/`:

```sh
cd ..
latexmk -pdf -interaction=nonstopmode -halt-on-error relatorio.tex
```

O arquivo de entrega é `relatorio.pdf`. As figuras da coleta principal já estão
incluídas no repositório.

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
