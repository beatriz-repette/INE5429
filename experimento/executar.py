#!/usr/bin/env python3
"""Executa a matriz experimental do trabalho (TLS 1.3 clássico x pós-quântico).

Topologia:  cliente (10.77.1.10) <-> roteador <-> servidor (10.77.2.10)

O roteador aplica o tc netem (atraso e perda) na saída das suas duas
interfaces, ou seja, nos dois sentidos, e captura com tcpdump os pacotes que
chegam a ele, ANTES da perda. Assim, as capturas mostram também os pacotes que
a rede descartou, o que permite contar as retransmissões corretamente.

Uso:  python3 executar.py [--repeticoes N] [--piloto]
Precisa só de Python 3 e Docker (sem sudo). Resultados em resultados/.
"""
import argparse
import csv
import itertools
import platform
import subprocess
import sys
import time
from pathlib import Path

AQUI = Path(__file__).resolve().parent
IMG = "tls-pq-experimento"
GRUPOS = {  # nome no relatório -> grupos oferecidos pelo cliente
    "X25519": "X25519",
    "X25519MLKEM768": "X25519MLKEM768",
    "MLKEM768": "MLKEM768",
    "Padrão OpenSSL": "padrao",  # X25519MLKEM768 + X25519 (2 chaves)
}
PERDAS = [0, 1, 5, 10]          # % por pacote, em cada sentido
ATRASOS = [10, 50, 150]         # ms por sentido
TIMEOUT_S = 10                  # limite por operação bloqueante do cliente
GRUPOS_SERVIDOR = "X25519MLKEM768:MLKEM768:X25519"


def sh(*cmd, check=True, captura=True):
    r = subprocess.run(cmd, text=True, capture_output=captura)
    if check and r.returncode != 0:
        sys.exit(f"falhou: {' '.join(cmd)}\n{r.stderr}")
    return r.stdout if captura else ""


def dexec(container, comando, check=True):
    return sh("docker", "exec", container, "sh", "-c", comando, check=check)


def limpar():
    for c in ("exp-cliente", "exp-servidor", "exp-roteador"):
        subprocess.run(["docker", "rm", "-f", c], capture_output=True)
    for n in ("exp-cli", "exp-srv"):
        subprocess.run(["docker", "network", "rm", n], capture_output=True)


def montar_ambiente(capturas: Path):
    sh("docker", "build", "-q", "-t", IMG, str(AQUI))
    limpar()
    for nome, sub in (("exp-cli", "10.77.1.0/24"), ("exp-srv", "10.77.2.0/24")):
        sh("docker", "network", "create", "--subnet", sub,
           "--opt", "com.docker.network.driver.mtu=1500", nome)

    sem_offload = ("for i in $(ls /sys/class/net | grep -v lo); do "
                   "ethtool -K $i tso off gso off gro off >/dev/null 2>&1; done")
    # Roteador: encaminha pacotes entre as duas redes e aplica o netem.
    sh("docker", "run", "-d", "--name", "exp-roteador", "--network", "exp-cli",
       "--ip", "10.77.1.254", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
       "--sysctl", "net.ipv4.ip_forward=1", "-v", f"{capturas}:/cap",
       IMG, "sleep", "infinity")
    sh("docker", "network", "connect", "--ip", "10.77.2.254", "exp-srv", "exp-roteador")
    dexec("exp-roteador", sem_offload)

    # Servidor: certificado ECDSA P-256 clássico; nada de session tickets
    # (cada tentativa é um handshake completo, sem retomada).
    sh("docker", "run", "-d", "--name", "exp-servidor", "--network", "exp-srv",
       "--ip", "10.77.2.10", "--cap-add", "NET_ADMIN",
       "--sysctl", "net.ipv4.tcp_no_metrics_save=1", IMG, "sh", "-c",
       f"{sem_offload}; ip route add 10.77.1.0/24 via 10.77.2.254; "
       "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
       "-subj /CN=servidor -days 30 -keyout /key.pem -out /cert.pem 2>/dev/null; "
       "while true; do openssl s_server -quiet -accept 4433 -tls1_3 -num_tickets 0 "
       f"-cert /cert.pem -key /key.pem -groups {GRUPOS_SERVIDOR} </dev/null; done")

    # Cliente. tcp_no_metrics_save=1 impede que o kernel reaproveite RTT e
    # RTO medidos em conexões anteriores, mantendo as tentativas independentes.
    sh("docker", "run", "-d", "--name", "exp-cliente", "--network", "exp-cli",
       "--ip", "10.77.1.10", "--cap-add", "NET_ADMIN",
       "--sysctl", "net.ipv4.tcp_no_metrics_save=1", IMG, "sleep", "infinity")
    dexec("exp-cliente", f"{sem_offload}; ip route add 10.77.2.0/24 via 10.77.1.254")
    time.sleep(3)


def interfaces_roteador():
    saida = dexec("exp-roteador", "ip -o -4 addr show | awk '{print $2}' | grep -v lo")
    return saida.split()


def aplicar_netem(ifs, atraso, perda):
    regra = f"delay {atraso}ms" + (f" loss {perda}%" if perda else "")
    for i in ifs:
        dexec("exp-roteador", f"tc qdisc replace dev {i} root netem {regra} limit 10000")


def remover_netem(ifs):
    for i in ifs:
        dexec("exp-roteador", f"tc qdisc del dev {i} root", check=False)


def registrar_ambiente(destino: Path, ifs):
    linhas = [
        f"data: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"host: {platform.system()} {platform.release()}",
        f"docker: {sh('docker', 'version', '--format', '{{.Server.Version}}').strip()}",
        f"openssl (containers): {dexec('exp-cliente', 'openssl version').strip()}",
        f"interfaces do roteador: {' '.join(ifs)}",
        f"MTU cliente: {dexec('exp-cliente', 'cat /sys/class/net/eth0/mtu').strip()}",
        f"timeout por operacao: {TIMEOUT_S} s",
    ]
    destino.write_text("\n".join(linhas) + "\n")
    print("\n".join(linhas))


def rodar_cenario(nome_cen, grupo, reps, ifs, atraso, perda):
    aplicar_netem(ifs, atraso, perda)
    try:
        dexec("exp-roteador", f"tcpdump -i any -Q in -U -s 200 -w /cap/{nome_cen}.pcap "
                              f"tcp port 4433 >/dev/null 2>&1 & echo $! > /tmp/tcpdump.pid")
        time.sleep(1)
        saida = sh("docker", "exec", "exp-cliente", "cliente-tls", "10.77.2.10", "4433",
                   GRUPOS[grupo], str(reps), str(TIMEOUT_S))
        time.sleep(1)
        dexec("exp-roteador", "kill -INT $(cat /tmp/tcpdump.pid); sleep 1")
    finally:
        remover_netem(ifs)  # mesmo se der erro
    return list(csv.DictReader(saida.splitlines()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeticoes", type=int, default=30)
    ap.add_argument("--piloto", action="store_true", help="3 handshakes por grupo, sem netem")
    args = ap.parse_args()

    res = AQUI / ("piloto" if args.piloto else "resultados")
    capturas = res / "capturas"
    capturas.mkdir(parents=True, exist_ok=True)
    montar_ambiente(capturas)
    try:
        ifs = interfaces_roteador()
        registrar_ambiente(res / "ambiente.txt", ifs)
        if args.piloto:
            cenarios = [(g, 0, 0) for g in GRUPOS]
            reps = 3
        else:
            # grupo no laço mais interno: os grupos de um mesmo cenário de rede
            # rodam em sequência, sob as mesmas condições da máquina.
            cenarios = [(g, p, a) for p, a, g in itertools.product(PERDAS, ATRASOS, GRUPOS)]
            reps = args.repeticoes

        campos = ["cenario", "grupo", "perda_pct", "atraso_ms", "repeticao", "porta_cliente",
                  "sucesso", "erro", "tcp_ms", "tls_ms", "total_ms", "retrans_cliente"]
        with open(res / "medicoes.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=campos)
            w.writeheader()
            inicio = time.time()
            for k, (g, p, a) in enumerate(cenarios, 1):
                nome = f"{GRUPOS[g]}_p{p}_a{a}"
                linhas = rodar_cenario(nome, g, reps, ifs, a, p)
                for l in linhas:
                    w.writerow({"cenario": nome, "grupo": g, "perda_pct": p, "atraso_ms": a, **l})
                f.flush()
                ok = sum(l["sucesso"] == "1" for l in linhas)
                print(f"[{k}/{len(cenarios)}] {nome}: {ok}/{len(linhas)} ok "
                      f"({(time.time() - inicio) / 60:.1f} min)", flush=True)
    finally:
        import os
        dexec("exp-roteador", f"chown -R {os.getuid()}:{os.getgid()} /cap", check=False)
        limpar()
    print(f"\nPronto. Resultados em {res}")


if __name__ == "__main__":
    main()
