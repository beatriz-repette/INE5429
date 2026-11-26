#!/usr/bin/env bash
# Mini-exemplo (seção 2.5): captura um handshake TLS 1.3 por configuração de grupo
# entre dois containers com OpenSSL 3.5 ligados por uma rede Docker (MTU 1500).
# Gera capturas/<config>.pcap e imprime as medidas de cada uma.
# Uso: ./capturar.sh   (precisa de Docker; não precisa de sudo)
set -euo pipefail
cd "$(dirname "$0")"

IMG=tls-pq-captura
REDE=tls-pq
GRUPOS_SERVIDOR="X25519MLKEM768:MLKEM768:X25519"
# nome do arquivo -> grupos que o cliente oferece ("padrao" = sem -groups, padrão do OpenSSL 3.5)
CONFIGS=(x25519:X25519 x25519mlkem768:X25519MLKEM768 mlkem768:MLKEM768 padrao-openssl:padrao)

mkdir -p capturas
docker build -q -t "$IMG" . >/dev/null
docker run --rm "$IMG" openssl version

limpar() { docker rm -f servidor >/dev/null 2>&1 || true; docker network rm "$REDE" >/dev/null 2>&1 || true; }
trap limpar EXIT
limpar
docker network create --opt com.docker.network.driver.mtu=1500 "$REDE" >/dev/null

# Servidor: certificado ECDSA P-256 clássico (só a troca de chaves varia).
# Offloads desligados para os pacotes capturados terem o tamanho real (<= MTU).
docker run -d --name servidor --network "$REDE" --cap-add NET_ADMIN "$IMG" sh -c "
  ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj /CN=servidor -days 30 -keyout /key.pem -out /cert.pem 2>/dev/null
  exec openssl s_server -quiet -accept 4433 -tls1_3 -cert /cert.pem -key /key.pem \
    -groups $GRUPOS_SERVIDOR" >/dev/null
sleep 2

for c in "${CONFIGS[@]}"; do
  nome=${c%%:*}; grupos=${c#*:}
  [ "$grupos" = padrao ] && opt="" || opt="-groups $grupos"
  echo
  echo "== $nome (cliente oferece: $grupos) =="
  docker run --rm --network "$REDE" --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$PWD:/w" "$IMG" sh -c "
      ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1
      tcpdump -i eth0 -U -s 0 -w /w/capturas/$nome.pcap tcp port 4433 2>/dev/null &
      sleep 1
      openssl s_client -connect servidor:4433 -tls1_3 $opt </dev/null >/dev/null 2>&1 || true
      sleep 1; kill %1; wait
      echo \"  MSS anunciado no SYN: \$(tshark -r /w/capturas/$nome.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.options.mss_val)\"
      sh /w/analisar.sh /w/capturas/$nome.pcap
      chown $(id -u):$(id -g) /w/capturas/$nome.pcap"
done
echo
echo "Capturas salvas em $PWD/capturas/ (abrir no Wireshark)."
