/* wolfserver.c */

/*
 gcc -Wall wolfserver.c -o ./server -lwolfssl

 will send time msg every second to group
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
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>


#define GROUP_ADDR "226.0.0.3"
#define GROUP_PORT  12345
#define MSG_SIZE    80


void sys_err(const char* str)
{
    fprintf(stderr, "error: %s\n", str);
    exit(EXIT_FAILURE);
}


int main(int argc, char** argv)
{
    int txfd, ret, on = 1;
    struct sockaddr_in transmit;
    int transmit_len = sizeof(transmit);
#ifdef WOLFSSL_STATIC_MEMORY
    byte memory[80000];
    byte memoryIO[34500];
#endif

    wolfSSL_Init();

    txfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (txfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    memset(&transmit, 0, transmit_len);
    transmit.sin_family = AF_INET;
    transmit.sin_addr.s_addr = inet_addr(GROUP_ADDR);
    transmit.sin_port = htons(GROUP_PORT);

    setsockopt(txfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(txfd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t)sizeof(on));
#endif

    WOLFSSL_CTX* ctx = NULL;

#ifndef WOLFSSL_STATIC_MEMORY
    ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, wolfDTLSv1_2_server_method_ex,
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

    ret = wolfSSL_CTX_mcast_set_member_id(ctx, 0);
    if (ret != SSL_SUCCESS) sys_err("set mcast member id error");

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) sys_err("ssl new error");

    ret = wolfSSL_set_write_fd(ssl, txfd);
    if (ret != SSL_SUCCESS) sys_err("set ssl write fd error");

    ret = wolfSSL_dtls_set_peer(ssl, &transmit, transmit_len);
    if (ret != SSL_SUCCESS) sys_err("set ssl sender error");

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

    for(;;) {
        char msg[80];
        time_t t = time(0);
        sprintf(msg, "time is %-24.24s", ctime(&t));
        printf("sending msg = %s\n", msg);
        size_t msg_len = strlen(msg) + 1;
        int n = wolfSSL_write(ssl, msg, (unsigned int)msg_len);
        if (n < 0) {
            n = wolfSSL_get_error(ssl, n);
            fprintf(stderr, "sendto error: %s\n",
                    wolfSSL_ERR_reason_error_string(n));
            exit(EXIT_FAILURE);
        }

        sleep(1);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
