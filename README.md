# TLS pós-quântico em redes degradadas

Trabalho de Segurança em Computação (INE5429/UFSC). O experimento mede quanto tempo o cliente leva para concluir um handshake TLS 1.3 com quatro configurações de troca de chaves: X25519, X25519MLKEM768, MLKEM768 e o padrão do OpenSSL 3.5. Um roteador emulado aplica atraso e perda de pacotes entre o cliente e o servidor.

Para conferir os números do PDF, siga as etapas 1 e 2. Para observar o experimento em execução, siga também a etapa 3. [Relatório completo em PDF](relatorio.pdf) · [Descrição técnica e instruções para compilar o relatório](experimento/README.md)

## 1. Preparar o ambiente

Use Linux com Git, Python 3 e acesso ao serviço Docker. A primeira construção da imagem precisa de internet para obter o Alpine e os pacotes. O container inclui OpenSSL, tshark e as bibliotecas Python de análise.

```bash
git clone https://github.com/beatriz-repette/INE5429.git
cd INE5429
docker info
docker build -t tls-pq-experimento ./experimento
```

Se já baixou o projeto, abra o terminal na pasta que contém este README. Execute os próximos blocos nessa pasta e na mesma sessão de Bash.

## 2. Validar os resultados do relatório

A coleta de 24/11/2026 foi registrada no commit `2937eab`, com OpenSSL 3.5.9 e MTU de 1.500 bytes. [Dados da coleta](experimento/resultados/) · [Versões e parâmetros do ambiente](experimento/resultados/ambiente.txt)

O bloco abaixo copia as durações registradas pelo cliente e as 48 capturas de pacotes para uma pasta temporária. O script combina cada medição com o tráfego da mesma conexão e gera novamente os CSVs e os gráficos.

```bash
reanalise=$(mktemp -d)
cp -r experimento/resultados/capturas experimento/resultados/medicoes.csv "$reanalise/"

analisar_tls() {
    docker run --rm --user "$(id -u):$(id -g)" -e MPLCONFIGDIR=/tmp \
        -v "$PWD/experimento/analisar.py:/analise.py:ro" \
        -v "$1:/dados" tls-pq-experimento python3 /analise.py /dados
}
analisar_tls "$reanalise"
```

Quem já tiver Python 3 com pandas, matplotlib e o executável tshark no Linux também pode executar a análise diretamente com `python3 experimento/analisar.py "$reanalise"`, após a cópia das entradas.

Compare os resultados recalculados com os publicados. Cada `diff` termina sem saída e com código zero quando os arquivos coincidem. Os gráficos gerados ficam em `$reanalise/figuras/`.

```bash
diff -u experimento/resultados/resumo.csv "$reanalise/resumo.csv"
diff -u experimento/resultados/lentos_por_perda.csv "$reanalise/lentos_por_perda.csv"
diff -u experimento/resultados/lentos_por_perda_de_syn.csv "$reanalise/lentos_por_perda_de_syn.csv"
```

| O que conferir | Onde verificar | Resultado da coleta publicada |
|---|---|---|
| Total de tentativas | `resumo.csv`, colunas `tentativas` e `sucesso_pct` | 48 cenários × 100 tentativas. Houve 4.799 sucessos e uma falha. |
| Efeito de 10% de perda | `lentos_por_perda.csv`, linhas com `perda_pct=10` | X25519 teve 77/300 handshakes lentos (25,67%). O padrão OpenSSL teve 126/300 (42,00%). Os três atrasos estão agrupados. |
| Atraso médio adicional | Mesma linha do padrão OpenSSL, coluna `extra_medio_ms` | 286,74 ms. A referência de cada tentativa é a mediana sem perda do mesmo grupo e atraso. |
| Evidência de retransmissão | Abra [padrao_p10_a10.pcap](experimento/resultados/capturas/padrao_p10_a10.pcap) no Wireshark e filtre com `tcp.port == 40576` | O quadro 41 leva os últimos 3 bytes do ClientHello. O quadro 43 repete esses bytes cerca de 242,60 ms depois. |

Uma conexão concluída conta como lenta quando o tempo TLS supera a mediana de referência acrescida do atraso por sentido e de 5 ms. A tentativa que falhou entra na contagem de lentas e fica fora das médias de duração.

## 3. Executar o experimento

O piloto monta a topologia Docker local e faz três tentativas por configuração, sem atraso ou perda adicionais. Use um ambiente em que os nomes de containers `exp-cliente`, `exp-roteador`, `exp-servidor` e das redes `exp-cli` e `exp-srv` estejam disponíveis. O script recria esses recursos durante a coleta.

```bash
piloto=$(mktemp -d)
python3 experimento/executar.py --piloto --saida "$piloto"
```

O piloto deve informar `3/3 ok` para cada uma das quatro configurações. Ao final, `$piloto/medicoes.csv` deve conter 12 medições e `$piloto/capturas/` deve conter quatro arquivos PCAP.

Para repetir a matriz do relatório, reserve cerca de 90 minutos. Ela combina as quatro configurações com perdas de 0%, 1%, 5% e 10% e atrasos de 10, 50 e 150 ms por sentido. A opção `--saida` direciona a coleta para uma pasta nova. Use a função da etapa 2 para gerar as tabelas dessa execução.

```bash
coleta=$(mktemp -d)
python3 experimento/executar.py --repeticoes 100 --saida "$coleta"
analisar_tls "$coleta"
```

Em uma nova coleta, confira os 48 cenários, as 100 tentativas por cenário e as 48 capturas. Os tempos e os percentuais podem variar porque as perdas são aleatórias. Para reproduzir os valores exatos apresentados no PDF, use as capturas publicadas na etapa 2.

## Mini-exemplo da Seção 2.5

A pasta [captura/](captura/) tem os scripts e as capturas do mini-exemplo, que mostra em quantos segmentos TCP o ClientHello e a resposta do servidor viajam em cada configuração, sem atraso nem perda. Para repetir, execute `./captura/capturar.sh` (precisa só de Docker).
