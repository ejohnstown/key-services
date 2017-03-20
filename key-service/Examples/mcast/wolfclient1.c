/* wolfclient1.c */

/*
 gcc -Wall wolfclient1.c -o ./wolfclient1 -lwolfssl

 run different clients on different hosts to see client sends,
 this is because we're disabling MULTICAST_LOOP so that we don't have to
 process messages we send ourselves

 could run ./server on host 1 (this sends out a time msg every second)
 then run  ./client on host 1 (will see server time msgs)
 then      ./client on host 2 (will see server and client 1msgs, and
                                         host1 will see host2 msgs as well)

 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/memory.h>


#define GROUP_ADDR "226.0.0.3"
#define GROUP_PORT  12345
#define MSG_SIZE    80


void sys_err(const char* str)
{
    fprintf(stderr, "error: %s\n", str);
    exit(EXIT_FAILURE);
}


static int seq_cb(word16 peerId, word32 maxSeq, word32 curSeq, void* ctx)
{
    char* ctxStr = (char*)ctx;

    printf("Highwater Callback (%u:%u/%u): %s\n", peerId, curSeq, maxSeq,
          ctxStr != NULL ? ctxStr : "Forgot to set the callback context.");

    return 0;
}


int main(int argc, char** argv)
{
    int rxfd, txfd, ret, on = 1, off = 0;
    struct sockaddr_in receive, transmit;
    socklen_t receive_len = sizeof(receive), transmit_len = sizeof(transmit);
    pid_t self = getpid();
    char seqHwCbCtx[] = "Callback context string.";
#ifdef WOLFSSL_STATIC_MEMORY
    byte memory[80000];
    byte memoryIO[34500];
#endif

    wolfSSL_Init();

    rxfd = socket(AF_INET, SOCK_DGRAM, 0);
    txfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rxfd < 0 || txfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    memset(&receive, 0, receive_len);
    receive.sin_family = AF_INET;
    receive.sin_addr.s_addr = htonl(INADDR_ANY);  /* don't bind to multi addr */
    receive.sin_port = htons(GROUP_PORT);

    memset(&transmit, 0, transmit_len);
    transmit.sin_family = AF_INET;
    transmit.sin_addr.s_addr = inet_addr(GROUP_ADDR);
    transmit.sin_port = htons(GROUP_PORT);

    setsockopt(rxfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
    setsockopt(txfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(rxfd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t)sizeof(on));
    setsockopt(txfd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t)sizeof(on));
#endif
    /* don't send to self */
    ret = setsockopt(txfd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
    if (ret < 0) {
        perror("setsockopt multicast loop off failed");
        exit(EXIT_FAILURE);
    }

    ret = bind(rxfd, (struct sockaddr*)&receive, receive_len);
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    {
        struct ip_mreq imreq;
        memset(&imreq, 0, sizeof(imreq));

        imreq.imr_multiaddr.s_addr = inet_addr(GROUP_ADDR);
        imreq.imr_interface.s_addr = INADDR_ANY;

        ret = setsockopt(rxfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         (const void*)&imreq, sizeof(imreq));
        if (ret < 0) {
            perror("setsockopt mc add membership failed");
            exit(EXIT_FAILURE);
        }
    }

    fcntl(rxfd, F_SETFL, O_NONBLOCK);

    WOLFSSL_CTX* ctx = NULL;

#ifndef WOLFSSL_STATIC_MEMORY
    ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, wolfDTLSv1_2_client_method_ex,
            memory, sizeof(memory), 0, 1);
    if (ret != SSL_SUCCESS)
        sys_err("unable to load static memory and create ctx");

    /* load in a buffer for IO */
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, NULL, memoryIO, sizeof(memoryIO),
            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
    if (ret != SSL_SUCCESS)
        sys_err("unable to load static IO memory and create ctx");
#endif
    if (!ctx) sys_err("ctx new error");

    ret = wolfSSL_CTX_mcast_set_member_id(ctx, 13);
    if (ret != SSL_SUCCESS) sys_err("set mcast member id error");

    ret = wolfSSL_CTX_mcast_set_highwater_cb(ctx, 100, 10, 20, seq_cb);
    if (ret != SSL_SUCCESS) sys_err("set mcast highwater cb error");

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) sys_err("ssl new error");

    ret = wolfSSL_set_read_fd(ssl, rxfd);
    if (ret != SSL_SUCCESS) sys_err("set ssl read fd error");

    ret = wolfSSL_set_write_fd(ssl, txfd);
    if (ret != SSL_SUCCESS) sys_err("set ssl write fd error");

    ret = wolfSSL_dtls_set_peer(ssl, &transmit, transmit_len);
    if (ret != SSL_SUCCESS) sys_err("set ssl sender error");

    ret = wolfSSL_mcast_set_highwater_ctx(ssl, seqHwCbCtx);
    if (ret != SSL_SUCCESS) sys_err("set highwater ctx error");

    ret = wolfSSL_mcast_peer_add(ssl, 0, 0);   /* server */
    if (ret != SSL_SUCCESS) sys_err("mcast add peer 0 error");
    ret = wolfSSL_mcast_peer_add(ssl, 23, 0);  /* client 2 */
    if (ret != SSL_SUCCESS) sys_err("mcast add peer 23 error");
    ret = wolfSSL_mcast_peer_add(ssl, 255, 0); /* client 3 */
    if (ret != SSL_SUCCESS) sys_err("mcast add peer 255 error");

    wolfSSL_set_using_nonblock(ssl, 1);

    {
        unsigned char pms[512];
        unsigned char cr[32];
        unsigned char sr[32];
        const unsigned char suite[2] = {0, 0xFE};  /* WDM_WITH_NULL_SHA256 */

        memset(pms, 0x23, sizeof(pms));
        memset(cr, 0xA5, sizeof(cr));
        memset(sr, 0x5A, sizeof(sr));

        ret = wolfSSL_set_secret(ssl, 1, pms, sizeof(pms), cr, sr, suite);
        if (ret != SSL_SUCCESS) sys_err("cannot set ssl secret error");
    }

    int i = 0;
    time_t txtime = time(NULL) + 3;

    for(;;) {
        char msg[MSG_SIZE];
        fd_set readfds;
        int ret;
        struct timeval timeout = {0, 500000};
        unsigned short peerId;

        FD_ZERO(&readfds);
        FD_SET(rxfd, &readfds);
        ret = select(rxfd+1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) sys_err("main select failed");

        if (FD_ISSET(rxfd, &readfds)) {
            ssize_t n = wolfSSL_mcast_read(ssl, &peerId, msg, MSG_SIZE);
            if (n < 0) {
                n = wolfSSL_get_error(ssl, n);
                if (n != SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "recvfrom error: %s\n",
                            wolfSSL_ERR_reason_error_string(n));
                    exit(EXIT_FAILURE);
                }
            }
            else
                printf("got msg from peer %u %s\n", peerId, msg);
        }

        time_t rxtime = time(NULL);
        if (rxtime >= txtime) {
            sprintf(msg, "%u sending message %d", self, i++);
            size_t msg_len = strlen(msg) + 1;
            int n = wolfSSL_write(ssl, msg, (unsigned int)msg_len);
            if (n < 0) {
                n = wolfSSL_get_error(ssl, n);
                fprintf(stderr, "sendto error: %s\n",
                        wolfSSL_ERR_reason_error_string(n));
                exit(EXIT_FAILURE);
            }

            txtime = rxtime + 3;
        }
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
