#!/usr/bin/env python3
"""Análise dos resultados: junta as medições do cliente com as métricas das
capturas e gera o resumo por cenário e os gráficos usados no relatório.

Roda dentro da imagem do experimento (precisa de tshark, pandas e matplotlib):
  docker run --rm -v "$PWD:/w" -w /w tls-pq-experimento python3 analisar.py resultados
"""
import subprocess
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

CLIENTE = "10.77.1.10"
ORDEM = ["X25519", "X25519MLKEM768", "MLKEM768", "Padrão OpenSSL"]
CORES = {"X25519": "#3D5A80", "X25519MLKEM768": "#D9622B",
         "MLKEM768": "#E9A23B", "Padrão OpenSSL": "#B3261E"}
MARCAS = {"X25519": "o", "X25519MLKEM768": "s", "MLKEM768": "^", "Padrão OpenSSL": "D"}


def metricas_captura(pcap: Path) -> pd.DataFrame:
    """Uma linha por conexão (identificada pela porta do cliente)."""
    campos = ["ip.src", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.flags.syn",
              "tcp.flags.ack", "tcp.analysis.retransmission",
              "tcp.analysis.fast_retransmission"]
    cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-E", "separator=\t"]
    for c in campos:
        cmd += ["-e", c]
    saida = subprocess.run(cmd, capture_output=True, text=True).stdout
    conexoes = {}
    for linha in saida.splitlines():
        src, sport, dport, tlen, syn, ack, retr, fretr = (linha.split("\t") + [""] * 8)[:8]
        do_cliente = src == CLIENTE
        porta = int(sport if do_cliente else dport)
        c = conexoes.setdefault(porta, dict(porta_cliente=porta, syn_enviados=0, synack_enviados=0,
                                            seg_cli=0, bytes_cli=0, seg_srv=0, bytes_srv=0,
                                            retrans_cli=0, retrans_srv=0,
                                            seg_ch=0, seg_resp=0, bytes_resp=0, _fase=0))
        tlen = int(tlen or 0)
        retransmissao = bool(retr or fretr)
        if syn in ("1", "True"):  # tshark recente escreve as flags como True/False
            if ack in ("0", "False"):
                c["syn_enviados"] += 1
            else:
                c["synack_enviados"] += 1
            continue
        if tlen == 0:
            continue
        # _fase 0: ClientHello; 1: resposta do servidor (ServerHello ... Finished);
        # 2: depois que o cliente envia o seu Finished.
        if do_cliente:
            c["seg_cli"] += 1
            c["bytes_cli"] += tlen
            c["retrans_cli"] += retransmissao
            if c["_fase"] == 0 and not retransmissao:
                c["seg_ch"] += 1
            elif c["_fase"] == 1 and not retransmissao:
                c["_fase"] = 2
        else:
            c["seg_srv"] += 1
            c["bytes_srv"] += tlen
            c["retrans_srv"] += retransmissao
            if c["_fase"] == 0:
                c["_fase"] = 1
            if c["_fase"] == 1 and not retransmissao:
                c["seg_resp"] += 1
                c["bytes_resp"] += tlen
    df = pd.DataFrame(conexoes.values())
    return df.drop(columns="_fase") if not df.empty else df


def wilson(k, n, z=1.96):
    """Intervalo de confiança de 95% de Wilson para uma proporção k/n."""
    if n == 0:
        return (0.0, 0.0)
    ph = k / n
    centro = (ph + z * z / (2 * n)) / (1 + z * z / n)
    margem = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5) / (1 + z * z / n)
    return (max(0.0, centro - margem), min(1.0, centro + margem))


def p95(s):
    return s.quantile(0.95)


def main(pasta: str):
    res = Path(pasta)
    fig_dir = res / "figuras"
    fig_dir.mkdir(exist_ok=True)
    med = pd.read_csv(res / "medicoes.csv")

    partes = []
    for cen in med["cenario"].unique():
        m = metricas_captura(res / "capturas" / f"{cen}.pcap")
        m["cenario"] = cen
        partes.append(m)
    cap = pd.concat(partes)
    df = med.merge(cap, on=["cenario", "porta_cliente"], how="left")
    df["retrans_dados"] = df["retrans_cli"].fillna(0) + df["retrans_srv"].fillna(0)
    df["perdeu_syn"] = (df["syn_enviados"].fillna(1) > 1) | (df["synack_enviados"].fillna(1) > 1)
    df["teve_retrans_tls"] = df["retrans_dados"] > 0
    # Handshake "lento": pelo menos meio RTT (+5 ms) acima da mediana do mesmo
    # grupo e atraso sem perda. Qualquer recuperação de perda custa pelo menos
    # cerca de um RTT, então esse limiar separa quem precisou se recuperar.
    base = (df[(df["perda_pct"] == 0) & (df["sucesso"] == 1)]
            .groupby(["grupo", "atraso_ms"])["tls_ms"].median().rename("tls_base"))
    df = df.join(base, on=["grupo", "atraso_ms"])
    df["lento"] = (df["sucesso"] == 0) | (df["tls_ms"] > df["tls_base"] + df["atraso_ms"] + 5)
    df.to_csv(res / "medicoes_com_capturas.csv", index=False)

    ok = df[df["sucesso"] == 1]
    chaves = ["grupo", "perda_pct", "atraso_ms"]
    resumo = df.groupby(chaves).agg(
        tentativas=("sucesso", "size"),
        sucesso_pct=("sucesso", lambda s: 100 * s.mean()),
        seg_ch=("seg_ch", "median"),
        seg_resp=("seg_resp", "median"),
        bytes_cli=("bytes_cli", "median"),
        bytes_resp=("bytes_resp", "median"),
        conexoes_com_retrans_tls_pct=("teve_retrans_tls", lambda s: 100 * s.mean()),
        conexoes_com_perda_syn_pct=("perdeu_syn", lambda s: 100 * s.mean()),
    )
    tempos = ok.groupby(chaves).agg(
        tls_media=("tls_ms", "mean"), tls_mediana=("tls_ms", "median"),
        tls_dp=("tls_ms", "std"), tls_p95=("tls_ms", p95), tls_max=("tls_ms", "max"),
        total_media=("total_ms", "mean"), total_mediana=("total_ms", "median"),
        total_p95=("total_ms", p95),
    )
    resumo = resumo.join(tempos).reset_index()
    resumo["grupo"] = pd.Categorical(resumo["grupo"], ORDEM, ordered=True)
    resumo = resumo.sort_values(["atraso_ms", "perda_pct", "grupo"])
    resumo.round(2).to_csv(res / "resumo.csv", index=False)

    segs = df.groupby("grupo")[["seg_ch", "seg_resp"]].median().sum(axis=1)
    agrup = df.groupby(["grupo", "perda_pct"]).agg(
        tentativas=("lento", "size"), lentos=("lento", "sum"),
        retrans_pct=("teve_retrans_tls", lambda s: 100 * s.mean()),
        perda_syn_pct=("perdeu_syn", lambda s: 100 * s.mean()),
    ).reset_index()
    agrup["lentos_pct"] = 100 * agrup["lentos"] / agrup["tentativas"]
    ic = agrup.apply(lambda r: wilson(r["lentos"], r["tentativas"]), axis=1)
    agrup["ic95_inf"] = [100 * x[0] for x in ic]
    agrup["ic95_sup"] = [100 * x[1] for x in ic]
    agrup["segmentos_ch_mais_resposta"] = agrup["grupo"].map(segs)
    agrup["previsto_pct"] = 100 * (1 - (1 - agrup["perda_pct"] / 100) ** agrup["segmentos_ch_mais_resposta"])
    agrup["grupo"] = pd.Categorical(agrup["grupo"], ORDEM, ordered=True)
    agrup = agrup.sort_values(["perda_pct", "grupo"])
    agrup.round(2).to_csv(res / "lentos_por_perda.csv", index=False)

    perdas = sorted(df["perda_pct"].unique())
    atrasos = sorted(df["atraso_ms"].unique())
    plt.rcParams.update({"font.size": 10, "font.family": "serif"})

    # Figura 1: mediana e p95 do handshake TLS por perda, um painel por atraso.
    fig, eixos = plt.subplots(2, len(atrasos), figsize=(10, 6), sharex=True, squeeze=False)
    for j, a in enumerate(atrasos):
        for i, (col, nome) in enumerate([("tls_mediana", "Mediana"), ("tls_p95", "p95")]):
            ax = eixos[i][j]
            for g in ORDEM:
                d = resumo[(resumo["grupo"] == g) & (resumo["atraso_ms"] == a)]
                ax.plot(d["perda_pct"], d[col], marker=MARCAS[g], color=CORES[g], label=g)
            ax.set_title(f"{nome}, atraso {a} ms por sentido", fontsize=10)
            ax.set_xticks(perdas)
            ax.grid(alpha=0.3)
            if j == 0:
                ax.set_ylabel("handshake TLS (ms)")
            if i == 1:
                ax.set_xlabel("perda por pacote (%)")
    eixos[0][0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_dir / "tempo_tls_por_perda.pdf")
    fig.savefig(fig_dir / "tempo_tls_por_perda.png", dpi=150)

    # Figura 2: distribuição acumulada (CDF) do handshake TLS no cenário mais
    # degradado de cada atraso, onde as caudas aparecem.
    pior = max(perdas)
    fig, eixos = plt.subplots(1, len(atrasos), figsize=(10, 3.4), squeeze=False)
    eixos = eixos[0]
    for j, a in enumerate(atrasos):
        ax = eixos[j]
        for g in ORDEM:
            d = ok[(ok["grupo"] == g) & (ok["perda_pct"] == pior) & (ok["atraso_ms"] == a)]
            x = d["tls_ms"].sort_values().to_numpy()
            y = [(k + 1) / len(x) for k in range(len(x))]
            ax.step(x, y, where="post", color=CORES[g], label=g)
        lim = ok[(ok["perda_pct"] == pior) & (ok["atraso_ms"] == a)]["tls_ms"].quantile(0.99)
        ax.set_xlim(0, lim)
        ax.set_title(f"perda {pior}%, atraso {a} ms", fontsize=10)
        ax.set_xlabel("handshake TLS (ms)")
        ax.grid(alpha=0.3)
    eixos[0].set_ylabel("fração das conexões")
    eixos[0].legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(fig_dir / "cdf_tls_perda_max.pdf")
    fig.savefig(fig_dir / "cdf_tls_perda_max.png", dpi=150)

    # Figura 3: fração de conexões com retransmissão de dados no handshake TLS.
    agg = df.groupby(["grupo", "perda_pct"])["teve_retrans_tls"].mean().mul(100).reset_index()
    fig, ax = plt.subplots(figsize=(6, 3.4))
    largura = 0.2
    for k, g in enumerate(ORDEM):
        d = agg[agg["grupo"] == g]
        xs = [perdas.index(p) + (k - 1.5) * largura for p in d["perda_pct"]]
        ax.bar(xs, d["teve_retrans_tls"], largura, color=CORES[g], label=g)
    ax.set_xticks(range(len(perdas)))
    ax.set_xticklabels([f"{p}%" for p in perdas])
    ax.set_xlabel("perda por pacote")
    ax.set_ylabel("conexões com retransmissão (%)")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_dir / "retransmissoes.pdf")
    fig.savefig(fig_dir / "retransmissoes.png", dpi=150)

    # Figura 4: handshakes lentos (observado, com IC 95%) x previsão teórica.
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    desloc = {g: (k - 1.5) * 0.25 for k, g in enumerate(ORDEM)}
    for g in ORDEM:
        d = agrup[agrup["grupo"] == g]
        xs = [p + desloc[g] for p in d["perda_pct"]]
        ax.errorbar(xs, d["lentos_pct"],
                    yerr=[d["lentos_pct"] - d["ic95_inf"], d["ic95_sup"] - d["lentos_pct"]],
                    fmt=MARCAS[g], color=CORES[g], capsize=3, label=f"{g} (medido)")
        ax.plot(d["perda_pct"], d["previsto_pct"], ls="--", lw=1, color=CORES[g])
    ax.set_xticks(perdas)
    ax.set_xticklabels([f"{p}%" for p in perdas])
    ax.set_xlabel("perda por pacote (em cada sentido)")
    ax.set_ylabel("handshakes TLS lentos (%)")
    ax.plot([], [], ls="--", color="gray", label="previsto: $1-(1-p)^n$")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=7.5)
    fig.tight_layout()
    fig.savefig(fig_dir / "lentos_por_perda.pdf")
    fig.savefig(fig_dir / "lentos_por_perda.png", dpi=150)

    # Figura 5: handshakes lentos com e sem perda de SYN/SYN-ACK (perdas de 5 e 10%).
    d = df[df["perda_pct"] >= 5]
    syn = d.groupby(["grupo", "perdeu_syn"]).agg(n=("lento", "size"), k=("lento", "sum")).reset_index()
    syn["pct"] = 100 * syn["k"] / syn["n"]
    ic = syn.apply(lambda r: wilson(r["k"], r["n"]), axis=1)
    syn["ic95_inf"] = [100 * x[0] for x in ic]
    syn["ic95_sup"] = [100 * x[1] for x in ic]
    syn["grupo"] = pd.Categorical(syn["grupo"], ORDEM, ordered=True)
    syn = syn.sort_values(["grupo", "perdeu_syn"])
    syn.round(2).to_csv(res / "lentos_por_perda_de_syn.csv", index=False)
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    for k, g in enumerate(ORDEM):
        for j, perdeu in enumerate([False, True]):
            r = syn[(syn["grupo"] == g) & (syn["perdeu_syn"] == perdeu)].iloc[0]
            x = k + (j - 0.5) * 0.38
            ax.bar(x, r["pct"], 0.36, color=CORES[g], alpha=1.0 if perdeu else 0.45,
                   yerr=[[r["pct"] - r["ic95_inf"]], [r["ic95_sup"] - r["pct"]]], capsize=3)
    ax.set_xticks(range(len(ORDEM)))
    ax.set_xticklabels(ORDEM, fontsize=8.5)
    ax.set_ylabel("handshakes TLS lentos (%)")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color="gray", alpha=0.45, label="SYN e SYN-ACK entregues"),
                       Patch(color="gray", label="SYN ou SYN-ACK perdido")], fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "lentos_por_perda_de_syn.pdf")
    fig.savefig(fig_dir / "lentos_por_perda_de_syn.png", dpi=150)
    print(syn.round(1).to_string(index=False))

    print(agrup.round(1).to_string(index=False))
    print(resumo[["grupo", "perda_pct", "atraso_ms", "sucesso_pct", "seg_ch", "seg_resp",
                  "tls_mediana", "tls_p95", "conexoes_com_retrans_tls_pct"]]
          .round(1).to_string(index=False))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "resultados")
