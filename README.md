# TLS pós-quântico em redes degradadas

Trabalho da disciplina de Segurança em Computação (INE5429/UFSC), feito por
Ana Clara Gomes Guimarães, Beatriz Reis Repette e Micael Angelo Sabadin
Presotto. A ideia do trabalho é medir quanto o handshake do TLS 1.3 fica mais
lento quando a troca de chaves passa a usar o ML-KEM, cujas chaves são bem
maiores que as das curvas elípticas, em uma rede que perde pacotes. Para
isso, comparamos quatro configurações (X25519, X25519MLKEM768, MLKEM768 e o
padrão do OpenSSL 3.5) em uma rede emulada, em que um roteador acrescenta
atraso e perda entre o cliente e o servidor.

O [relatório completo](relatorio.pdf) explica a teoria, o experimento e os
resultados. Este README mostra como conferir os números do relatório a partir
dos dados coletados e como rodar o experimento de novo.

## O que tem em cada pasta

- [experimento/](experimento/) tem o código do experimento, com o
  cliente em C, os scripts de coleta e de análise e o Dockerfile. O
  [README dessa pasta](experimento/README.md) explica como cada parte
  funciona.
- [experimento/resultados/](experimento/resultados/) tem os dados usados no
  relatório, com as medições, as capturas de pacotes e os gráficos.
- [captura/](captura/) tem os scripts e as capturas do mini-exemplo da Seção
  2.5, que mostra em quantos segmentos TCP cada mensagem do handshake viaja.
- `relatorio.tex` e `relatorio.pdf` são o relatório e a versão compilada.

## Preparar o ambiente

Tudo roda em containers, então basta ter Linux com Git, Python 3 e Docker. A
imagem tem o OpenSSL 3.5, que já suporta o ML-KEM, além do tshark e das
bibliotecas Python usadas na análise, e na primeira vez que ela é construída
é preciso ter internet para baixar os pacotes.

```bash
git clone https://github.com/beatriz-repette/INE5429.git
cd INE5429
docker build -t tls-pq-experimento ./experimento
```

Os comandos das próximas seções devem ser executados nessa mesma pasta e no
mesmo terminal, já que alguns usam variáveis criadas antes.

## Conferir os resultados do relatório

A análise junta os tempos medidos pelo cliente com o que aparece nas capturas
de cada conexão e, a partir disso, gera as tabelas e os gráficos do
relatório. Para conferir que ela chega aos mesmos números, o bloco abaixo
copia os dados para uma pasta temporária e roda a análise de novo lá dentro,
sem mexer nos resultados publicados.

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

Depois, basta comparar os arquivos gerados com os publicados. Se os `diff`
terminarem sem mostrar nada, os resultados são idênticos, e os gráficos
gerados ficam em `$reanalise/figuras/`.

```bash
diff -u experimento/resultados/resumo.csv "$reanalise/resumo.csv"
diff -u experimento/resultados/lentos_por_perda.csv "$reanalise/lentos_por_perda.csv"
diff -u experimento/resultados/lentos_por_perda_de_syn.csv "$reanalise/lentos_por_perda_de_syn.csv"
```

A tabela abaixo indica alguns números do relatório e onde encontrar cada um
deles nos dados.

| O que conferir | Onde olhar | O que deve aparecer |
|---|---|---|
| Total de tentativas | `resumo.csv`, colunas `tentativas` e `sucesso_pct` | 48 cenários com 100 tentativas cada, com 4799 sucessos e uma falha |
| Handshakes lentos com 10% de perda | `lentos_por_perda.csv`, linhas com `perda_pct` igual a 10 | 77 de 300 no X25519 (25,7%) e 126 de 300 no padrão do OpenSSL (42,0%) |
| Atraso médio extra | mesma linha do padrão do OpenSSL, coluna `extra_medio_ms` | 286,74 ms |
| Uma retransmissão nas capturas | [padrao_p10_a10.pcap](experimento/resultados/capturas/padrao_p10_a10.pcap) no Wireshark, com o filtro `tcp.port == 40576` | o quadro 41 leva os últimos 3 bytes do ClientHello, que se perdem e são enviados de novo no quadro 43, cerca de 243 ms depois |

Um handshake conta como lento quando demora mais do que a mediana sem perda
da mesma configuração e do mesmo atraso, somada ao atraso por sentido e a uma
folga de 5 ms. A única tentativa que falhou também entra como lenta, mas fica
fora das médias de duração.

## Rodar o experimento

Antes de rodar a coleta completa, vale testar o ambiente com o piloto, que
sobe os três containers e faz três handshakes com cada configuração, sem
atraso nem perda. O script cria containers e redes com os nomes
`exp-cliente`, `exp-roteador`, `exp-servidor`, `exp-cli` e `exp-srv`, então é
bom garantir que não exista nada com esses nomes na máquina.

```bash
piloto=$(mktemp -d)
python3 experimento/executar.py --piloto --saida "$piloto"
```

Se tudo estiver certo, cada configuração mostra `3/3 ok`, e a pasta do piloto
fica com 12 medições em `medicoes.csv` e quatro capturas em `capturas/`.

A coleta completa combina as quatro configurações com perdas de 0, 1, 5 e
10% e atrasos de 10, 50 e 150 ms por sentido, com 100 tentativas em cada
cenário, e leva cerca de 90 minutos. A opção `--saida` grava tudo em uma
pasta nova, para não sobrescrever os resultados publicados, e a função da
seção anterior gera as tabelas e os gráficos dessa coleta.

```bash
coleta=$(mktemp -d)
python3 experimento/executar.py --repeticoes 100 --saida "$coleta"
analisar_tls "$coleta"
```

Como as perdas são aleatórias, os números de uma coleta nova não vão ser
exatamente iguais aos do relatório, mas devem seguir o mesmo comportamento.
Para chegar aos valores exatos, use os dados publicados, como na seção
anterior.

## Mini-exemplo

O mini-exemplo da Seção 2.5 captura um único handshake de cada configuração,
sem atraso nem perda, para mostrar o tamanho das mensagens e em quantos
segmentos elas são divididas. Para repetir, basta rodar o script abaixo, que
também só precisa de Docker.

```bash
./captura/capturar.sh
```

## Compilar o relatório

Com uma distribuição LaTeX que tenha pdfLaTeX, latexmk, TikZ e suporte ao
português, o relatório pode ser compilado na raiz do repositório. As figuras
dos resultados já estão no repositório, então não é preciso rodar a análise
antes.

```bash
latexmk -pdf relatorio.tex
```
