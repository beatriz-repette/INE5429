# Resultados do experimento

Esta pasta tem os dados da coleta usada no relatório, com as quatro
configurações testadas sob quatro taxas de perda e três atrasos, em 100
tentativas por cenário, o que somou 4800 handshakes.

| Arquivo | O que tem |
|---|---|
| `ambiente.txt` | as versões do Linux, do Docker e do OpenSSL e os parâmetros usados na coleta |
| `medicoes.csv` | uma linha por tentativa, com o que o cliente mediu (tempo da abertura TCP, tempo do handshake TLS, se deu certo e a porta usada pelo cliente) |
| `medicoes_com_capturas.csv` | as mesmas linhas, com os segmentos, bytes e retransmissões de cada conexão tirados das capturas |
| `resumo.csv` | as estatísticas de cada cenário, como média, mediana, desvio padrão e p95 |
| `lentos_por_perda.csv` | a porcentagem de handshakes lentos por configuração e taxa de perda, com o intervalo de confiança e a previsão da fórmula 1 − (1 − p)ⁿ, que aparecem na tabela de handshakes lentos do relatório |
| `lentos_por_perda_de_syn.csv` | os handshakes lentos separados pela perda do SYN ou do SYN-ACK, usados na Seção 4.3 |
| `capturas/` | uma captura por cenário, que abre no Wireshark |
| `figuras/` | os gráficos do relatório, em PDF e PNG |

As capturas seguem o nome `<configuração>_p<perda>_a<atraso>.pcap`, então
`padrao_p10_a50.pcap`, por exemplo, é o padrão do OpenSSL com 10% de perda e
50 ms de atraso. Dentro de cada uma, as conexões podem ser separadas pela
porta do cliente, que é a mesma registrada em `medicoes.csv`.

Para gerar estes arquivos de novo a partir das capturas, veja o
[README da raiz do repositório](../../README.md).
