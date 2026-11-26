#!/bin/sh
# Lê um .pcap de um handshake TLS 1.3 e imprime as medidas da Tabela tab:captura.
# Roda dentro do container (usa o tshark da imagem). Uso: analisar.sh arquivo.pcap
set -eu
pcap="$1"

# Quem é o cliente: origem do primeiro ClientHello
cli=$(tshark -r "$pcap" -Y 'tls.handshake.type == 1' -T fields -e ip.src | head -1)

# Medidas do próprio TLS (lidas depois de o Wireshark remontar os segmentos)
ch_len=$(tshark -r "$pcap" -Y 'tls.handshake.type == 1' -T fields -E occurrence=f -e tls.handshake.length | head -1)
ks_cli=$(tshark -r "$pcap" -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_key_share_key_exchange_length | head -1)
sh_len=$(tshark -r "$pcap" -Y 'tls.handshake.type == 2' -T fields -E occurrence=f -e tls.handshake.length | head -1)
ks_srv=$(tshark -r "$pcap" -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.extensions_key_share_key_exchange_length | head -1)
grupo=$(tshark -r "$pcap" -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.extensions_key_share_group | head -1)

# Segmentos TCP com dados, em ordem: "origem tamanho"
# 1º bloco do cliente = ClientHello; bloco seguinte do servidor = resposta do servidor
tshark -r "$pcap" -Y 'tcp.port == 4433 && tcp.len > 0' -T fields -e ip.src -e tcp.len |
awk -v cli="$cli" -v chl="$ch_len" -v ksc="$ks_cli" -v shl="$sh_len" -v kss="$ks_srv" -v g="$grupo" '
  BEGIN { fase = 0 }   # 0 = ClientHello, 1 = resposta do servidor, 2 = fim
  {
    if (fase == 0) { if ($1 == cli) { chb += $2; chs++ } else fase = 1 }
    if (fase == 1) { if ($1 != cli) { svb += $2; svs++ } else fase = 2 }
  }
  END {
    printf "  grupo escolhido pelo servidor: %s\n", g
    printf "  key_share do cliente:          %s bytes\n", ksc
    printf "  key_share do servidor:         %s bytes\n", kss
    printf "  ClientHello (mensagem):        %d bytes (+5 do registro TLS = %d no TCP)\n", chl + 4, chb
    printf "  segmentos do ClientHello:      %d\n", chs
    printf "  ServerHello (mensagem):        %d bytes\n", shl + 4
    printf "  resposta do servidor:          %d bytes em %d segmentos\n", svb, svs
  }'
