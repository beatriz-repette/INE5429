# Resultados do experimento

Dados da coleta usada no relatório: 4 configurações × 4 taxas de perda ×
3 atrasos × 100 tentativas = 4800 handshakes, coletados em 24/11/2026.

| Arquivo | O que tem |
|---|---|
| `ambiente.txt` | Data, versões (Linux, Docker, OpenSSL) e parâmetros da coleta. |
| `medicoes.csv` | Uma linha por tentativa, como o cliente mediu: tempo TCP, tempo TLS, sucesso ou falha e porta do cliente. |
| `medicoes_com_capturas.csv` | O mesmo, mais segmentos, bytes e retransmissões de cada conexão, tirados das capturas. |
| `resumo.csv` | Estatísticas por cenário: média, mediana, desvio padrão, p95 e taxa de sucesso. |
| `lentos_por_perda.csv` | Porcentagem de handshakes lentos por configuração e perda, com intervalo de confiança e previsão de 1 − (1 − p)ⁿ (Tabela de handshakes lentos do relatório). |
| `lentos_por_perda_de_syn.csv` | Handshakes lentos separados pela perda do SYN ou do SYN-ACK (Seção 4.3 do relatório). |
| `capturas/` | Um `.pcap` por cenário, com nome `<configuração>_p<perda>_a<atraso>.pcap`. Abrem no Wireshark; cada conexão é identificada pela porta do cliente. |
| `figuras/` | Gráficos do relatório, em PDF e PNG. |

A pasta `../resultados_30rep/` guarda uma primeira coleta com 30 tentativas
por cenário, que não é usada no relatório. As estimativas dos casos mais
lentos ficaram instáveis com esse número, o que motivou o aumento para 100.

Para gerar estes arquivos de novo a partir das capturas, veja o README da
raiz do repositório.
