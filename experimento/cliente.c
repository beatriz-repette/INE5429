/*
 * cliente-tls: faz N handshakes TLS 1.3 completos (sem retomada de sessão)
 * e mede, para cada um, o tempo do handshake TCP e o do handshake TLS.
 *
 * Uso: cliente-tls <host> <porta> <grupos|padrao> <repeticoes> <timeout_s>
 *
 * Saída (CSV, uma linha por tentativa):
 *   repeticao,porta_cliente,sucesso,erro,tcp_ms,tls_ms,total_ms,retrans_cliente
 *
 * O cronômetro começa imediatamente antes do connect(), então o tempo de
 * iniciar o programa não entra na medida. "tls_ms" vai do fim do connect()
 * até o SSL_connect() retornar, ou seja, até o cliente receber o Finished
 * do servidor e enviar o seu.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static double agora_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "uso: %s host porta grupos|padrao repeticoes timeout_s\n", argv[0]);
        return 2;
    }
    const char *host = argv[1], *porta = argv[2], *grupos = argv[3];
    int reps = atoi(argv[4]), timeout_s = atoi(argv[5]);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);       /* certificado autoassinado */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF); /* nunca retoma sessão */
    if (strcmp(grupos, "padrao") != 0 && SSL_CTX_set1_groups_list(ctx, grupos) != 1) {
        fprintf(stderr, "grupo nao suportado: %s\n", grupos);
        return 2;
    }

    struct addrinfo dicas = {0}, *end;
    dicas.ai_family = AF_INET;
    dicas.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, porta, &dicas, &end) != 0) {
        fprintf(stderr, "endereco invalido\n");
        return 2;
    }

    printf("repeticao,porta_cliente,sucesso,erro,tcp_ms,tls_ms,total_ms,retrans_cliente\n");
    for (int r = 1; r <= reps; r++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {timeout_s, 0};
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv); /* vale para o connect() */
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); /* vale para o SSL_connect() */

        const char *erro = "";
        double tcp_ms = -1, tls_ms = -1, total_ms = -1;
        int sucesso = 0, porta_cli = 0;

        double t0 = agora_ms();
        if (connect(s, end->ai_addr, end->ai_addrlen) != 0) {
            erro = "timeout_tcp";
        } else {
            double t1 = agora_ms();
            tcp_ms = t1 - t0;
            struct sockaddr_in local;
            socklen_t len = sizeof local;
            getsockname(s, (struct sockaddr *)&local, &len);
            porta_cli = ntohs(local.sin_port);

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, s);
            if (SSL_connect(ssl) == 1) {
                double t2 = agora_ms();
                tls_ms = t2 - t1;
                total_ms = t2 - t0;
                sucesso = 1;
            } else {
                erro = "falha_tls";
            }
            SSL_free(ssl);
        }
        if (!sucesso && total_ms < 0) total_ms = agora_ms() - t0;

        struct tcp_info info;
        socklen_t il = sizeof info;
        unsigned retrans = 0;
        if (getsockopt(s, IPPROTO_TCP, TCP_INFO, &info, &il) == 0) retrans = info.tcpi_total_retrans;
        close(s);

        printf("%d,%d,%d,%s,%.3f,%.3f,%.3f,%u\n", r, porta_cli, sucesso, erro,
               tcp_ms, tls_ms, total_ms, retrans);
        fflush(stdout);
        usleep(100 * 1000); /* folga para o servidor voltar ao accept() */
    }
    freeaddrinfo(end);
    SSL_CTX_free(ctx);
    return 0;
}
