#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "key-services.h"

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#ifndef KEY_SERVICE_LOGGING_LEVEL
    #define KEY_SERVICE_LOGGING_LEVEL   0
#endif

//#define KEY_SERVICE_FORCE_CLIENT_TO_USE_NET /* for testing */

#ifdef HAVE_NETX
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        #define printf bsp_debug_printf
    #endif
    #define htons(x) (x)
    extern NX_IP *nxIp;
#endif

#define KEY_SERVICE_RECV_TIMEOUT (1 * KEY_SERVICE_TICKS_PER_SECOND)

/*----------------------------------------------------------------------------*/
/* Server */
/*----------------------------------------------------------------------------*/

/* Generic responses for all supported packet types */
static CmdPacket_t*   gRespPkt[CMD_PKT_TYPE_COUNT];
static int            gRespPktLen[CMD_PKT_TYPE_COUNT];
static volatile int   gKeyServerInitDone = 0;
static int            gKeyServerRunning = 0;
static int            gKeyServerStop = 0;
static unsigned short gKeyServerEpoch;
static struct in_addr gBcastAddr;

#ifdef WOLFSSL_STATIC_MEMORY
    #if defined(NETX) && defined(PGB002)
        #define MEMORY_SECTION LINK_SECTION(data_sdram)
    #else
        #define MEMORY_SECTION
    #endif

    #if defined(NETX)
        /* Under NetX we'll have only one client thread. Non-NetX
         * will use a local buffer in the function since there can
         * be multiple clients. */
        static MEMORY_SECTION byte clientMemory[WOLFLOCAL_STATIC_MEMORY_SZ];
    #endif
    static MEMORY_SECTION byte serverMemory[WOLFLOCAL_STATIC_MEMORY_SZ];
#endif

enum {
    CMD_PKT_PUBLIC,
    CMD_PKT_PRIVATE,
};

static const int gRespPrivacy[CMD_PKT_TYPE_COUNT] = {
    CMD_PKT_PUBLIC, /* CMD_PKT_TYPE_DISCOVER */
    CMD_PKT_PUBLIC, /* CMD_PKT_TYPE_KEY_CHG */
    CMD_PKT_PUBLIC, /* CMD_PKT_TYPE_KEY_USE */
    CMD_PKT_PRIVATE,/* CMD_PKT_TYPE_KEY_REQ */
    CMD_PKT_PRIVATE,/* CMD_PKT_TYPE_KEY_NEW */
};

static int KeyClient_NetUdpBcast(const struct in_addr* srvAddr, int txMsgLen,
    unsigned char* txMsg, int* rxMsgLen, unsigned char* rxMsg);

/*
 * Identify which psk key to use.
 */
static unsigned int KeyServer_PskCb(WOLFSSL* ssl, const char* identity,
    unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;

    if (XSTRNCMP(identity, CLIENT_IDENTITY, XSTRLEN(CLIENT_IDENTITY)) != 0) {
        return 0;
    }

    if (key_max_len > sizeof(g_TlsPsk)) {
        key_max_len = sizeof(g_TlsPsk);
    }
    XMEMCPY(key, g_TlsPsk, key_max_len);

    return key_max_len;
}

static inline void c16toa(unsigned short u16, unsigned char* a)
{
    a[0] = (u16 >> 8) & 0xFF;
    a[1] = u16 & 0xFF;
}

static inline void ato16(const unsigned char* c, unsigned short* u16)
{
    *u16 = (c[0] << 8) | c[1];
}

static inline int BuildPacket(CmdPacket_t** pPkt, int type, int msgLen,
    const unsigned char* msg, void* heap)
{
    CmdPacket_t* pkt;

    /* make sure buffer has been allocated */
    if (gRespPkt[type] == NULL) {
        gRespPkt[type] = (CmdPacket_t*)XMALLOC(sizeof(CmdHeader_t) + msgLen,
            heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    pkt = gRespPkt[type];
    if (pkt == NULL)
        return MEMORY_E;

    /* populate packet header */
    pkt->header.version = CMD_PKT_VERSION;
    pkt->header.type = type;
    c16toa(msgLen, pkt->header.size);

    /* populate message */
    if (msg) {
        XMEMCPY(pkt->msg.raw, msg, msgLen);
    }

    /* set global indicating packet buffer size */
    gRespPktLen[type] = sizeof(CmdHeader_t) + msgLen;

    /* return packet pointer if requested */
    if (pPkt)
        *pPkt = pkt;

    return 0;
}

static int KeyReq_BuildKeyReq_Ex(unsigned char* pms, int pmsSz,
    unsigned char* serverRandom, int serverRandomSz,
    unsigned char* clientRandom, int clientRandomSz, void* heap)
{
    int ret = 0;
    WC_RNG rng;
    CmdPacket_t* pkt;

    ret = BuildPacket(&pkt, CMD_PKT_TYPE_KEY_REQ, MAX_PACKET_MSG, NULL, heap);
    if (ret != 0)
        return ret;

    /* get random data for message bytes */
    ret = wc_InitRng_ex(&rng, heap, 0);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, pkt->msg.raw, MAX_PACKET_MSG);
        if (ret != 0) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("RNG generate block failed!\n");
        #endif
        }

        wc_FreeRng(&rng);
    }

    if (ret == 0) {
        /* populate response packet */
        c16toa(++gKeyServerEpoch, pkt->msg.keyResp.epoch);
        pkt->msg.keyResp.suite[0] = CIPHER_SUITE_0;
        pkt->msg.keyResp.suite[1] = CIPHER_SUITE_1;

        /* use args if provided */
        if (pms) {
            if (pmsSz > PMS_SIZE) pmsSz = PMS_SIZE;
            XMEMCPY(pkt->msg.keyResp.pms, pms, pmsSz);
        }
        if (serverRandom) {
            if (serverRandomSz > RAND_SIZE) serverRandomSz = RAND_SIZE;
            XMEMCPY(pkt->msg.keyResp.serverRandom, serverRandom, serverRandomSz);
        }
        if (clientRandom) {
            if (clientRandomSz > RAND_SIZE) clientRandomSz = RAND_SIZE;
            XMEMCPY(pkt->msg.keyResp.clientRandom, clientRandom, clientRandomSz);
        }
    }

    return ret;
}

static int KeyReq_BuildKeyReq(void* heap)
{
    return KeyReq_BuildKeyReq_Ex(NULL, 0, NULL, 0, NULL, 0, heap);
}

static int KeyReq_BuildKeyUse(void* heap)
{
    unsigned char epoch[EPOCH_SIZE];

    c16toa(gKeyServerEpoch, epoch);
    return BuildPacket(NULL, CMD_PKT_TYPE_KEY_USE, sizeof(epoch), epoch, heap);
}

static void KeyReq_GetResp(int type, unsigned char** resp, int* respLen)
{
    /* set defaults */
    if (resp)
        *resp = NULL;
    if (respLen)
        *respLen = 0;

    /* check for valid type */
    if (type >= CMD_PKT_TYPE_COUNT || type <= CMD_PKT_TYPE_INVALID)
        return;

    /* return packet size */
    if (respLen)
        *respLen = gRespPktLen[type];

    /* return buffer to response */
    if (resp)
        *resp = (unsigned char*)&gRespPkt[type];
}

static int KeyReq_Check(CmdPacket_t* reqPkt, int privacy)
{
    int ret = 0;
    unsigned short size = 0;

    if (reqPkt == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get size */
    ato16(reqPkt->header.size, &size);

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    printf("Request: Version %d, Cmd %d, Size %d\n",
        reqPkt->header.version, reqPkt->header.type, size);
#endif

    /* verify command version */
    if (reqPkt->header.version != CMD_PKT_VERSION) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyReq_Check: Invalid request version\n");
    #endif
        return -1;
    }

    /* verify command type */
    if (reqPkt->header.type >= CMD_PKT_TYPE_COUNT) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyReq_Check: Invalid request type\n");
    #endif
        return -1;
    }

    /* check privacy - if type is private and privacy is public, reject */
    if (gRespPrivacy[reqPkt->header.type] == CMD_PKT_PRIVATE &&
                                  privacy == CMD_PKT_PUBLIC) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyReq_Check: Invalid privacy for request\n");
    #endif
        return -1;
    }

    /* return packet message (payload) size */
    ret = size;

    return ret;
}

int KeyServer_Init(void* heap)
{
    int ret = 0;

    if (++gKeyServerInitDone == 1) {
        const unsigned char ipaddr[4] = {KEY_SERV_LOCAL_ADDR};

        /* init each command type */
        ret = KeyReq_BuildKeyReq(heap);
        if (ret != 0)
            return ret;
        ret = KeyReq_BuildKeyUse(heap);
        if (ret != 0)
            return ret;

        ret = BuildPacket(NULL, CMD_PKT_TYPE_DISCOVER, sizeof(ipaddr), ipaddr, heap);
        if (ret != 0)
            return ret;
        ret = BuildPacket(NULL, CMD_PKT_TYPE_KEY_CHG, sizeof(ipaddr), ipaddr, heap);
        if (ret != 0)
            return ret;
    }

    return ret;
}

void KeyServer_Free(void* heap)
{
    if (--gKeyServerInitDone == 0) {
        int i;
        for (i=0; i<CMD_PKT_TYPE_COUNT; i++) {
            if (gRespPkt[i]) {
                XFREE(gRespPkt[i], heap, DYNAMIC_TYPE_TMP_BUFFER);
                gRespPkt[i] = NULL;
            }
        }
    }
}

static int KeyServer_InitCtx(WOLFSSL_CTX** pCtx, wolfSSL_method_func method_func, void* heap)
{
    int ret = 0;
    WOLFSSL_CTX* ctx = NULL;

    /* init the WOLFSSL_CTX */
    /* create and initialize WOLFSSL_CTX structure for TLS 1.2 only */
#ifndef WOLFSSL_STATIC_MEMORY
    WOLFSSL_METHOD* method = method_func(heap);
    ctx = wolfSSL_CTX_new(method);
#else
    (void)heap;
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, method_func,
            serverMemory, sizeof(serverMemory), 0, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: unable to load static memory and create ctx\n");
    #endif
    }
#endif

    if (ctx == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: wolfSSL_CTX_new error\n");
    #endif
        return MEMORY_E;
    }

    if (pCtx)
        *pCtx = ctx;

    /* use psk suite for security */
    wolfSSL_CTX_set_psk_server_callback(ctx, KeyServer_PskCb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, SERVER_IDENTITY);
    ret = wolfSSL_CTX_set_cipher_list(ctx, PSK_CIPHER_SUITE);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error %d: server can't set cipher list\n", ret);
    #endif
        ret = -1;
    }

    return ret;
}

int KeyBcast_RunUdp(const struct in_addr* srvAddr, KeyBcastReqPktCb reqCb, void* heap)
{
    int                 ret = 0;
#ifdef HAVE_NETX
    NX_UDP_SOCKET realSock;
    KS_SOCKET_T listenfd = (KS_SOCKET_T)&realSock;
#else
    KS_SOCKET_T listenfd = KS_SOCKET_T_INIT;
#endif
    const unsigned long inAddrAny = INADDR_ANY;
    int n;
    CmdPacket_t respPkt;
    CmdPacket_t* reqPkt = (CmdPacket_t*)&respPkt.header;
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen;

    (void)heap;

    /* copy address to global for key change */
    XMEMCPY(&gBcastAddr, srvAddr, sizeof(struct in_addr));

    /* create socket */
    ret = KeySocket_CreateUdpSocket(&listenfd);
    if (ret != 0) {
        goto exit;
    }

    /* setup socket as non-blocking */
    KeySocket_SetNonBlocking(listenfd);

    /* enable broadcast */
    KeySocket_SetBroadcast(listenfd);

    /* setup socket listener */
    ret = KeySocket_Bind(listenfd, (const struct in_addr*)&inAddrAny, KEY_BCAST_PORT, 1);
    if (ret != 0)
        goto exit;

    /* main loop for accepting and responding to clients */
    while (gKeyServerStop == 0) {
        /* wait for client */
        clientAddrLen = sizeof(clientAddr);

        XMEMSET(reqPkt, 0, sizeof(CmdPacket_t));

        /* get header */
        ret = KeySocket_RecvFrom(listenfd, (char*)reqPkt, sizeof(CmdPacket_t),
            0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (ret > 0) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 2
            unsigned char* addr = (unsigned char*)&clientAddr.sin_addr.s_addr;
            printf("Recieved Bcast from: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
        #endif
            /* check request */
            ret = KeyReq_Check(reqPkt, CMD_PKT_PUBLIC);
            if (ret < 0) {
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("KeyBcast_RunUdp Error: KeyReq_Check failed %d\n", ret);
            #endif
                continue;
            }

            if (ret > 0) {
                int tries = 1000;
                do {
                    /* get remainder of packet and issue callback */
                    ret = KeySocket_RecvFrom(listenfd, (char*)&respPkt.msg, ret,
                        0, (struct sockaddr*)&clientAddr, &clientAddrLen);
                    if (ret == WOLFSSL_CBIO_ERR_WANT_READ)
                        KEY_SERVICE_SLEEP(KEY_SERVICE_RECV_TIMEOUT);
                } while (--tries > 0 && ret == WOLFSSL_CBIO_ERR_WANT_READ);

                /* perform callback with packet */
                if (reqCb) {
                    reqCb(&respPkt);
                }
            }
            else {
                /* if we are key server then process incomming requests */
                if (gKeyServerRunning) {
                    unsigned char* resp = NULL;

                    /* get response */
                    KeyReq_GetResp(reqPkt->header.type, &resp, &n);

                    /* write response */
                    ret = KeySocket_SendTo(listenfd, (char*)resp, n, 0,
                        (struct sockaddr*)&clientAddr, clientAddrLen);
                    if (ret != n) {
                    #if KEY_SERVICE_LOGGING_LEVEL >= 1
                        printf("KeyBcast_RunUdp Error: SendTo %d\n", ret);
                    #endif
                    }
                }
            }
        }
        else if (ret == WOLFSSL_CBIO_ERR_WANT_READ) {
            /* no data (EAGAIN) */
            KEY_SERVICE_SLEEP(KEY_SERVICE_RECV_TIMEOUT);
            ret = 0;
        }
        else if (ret < 0) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("KeyBcast_RunUdp Error: RecvFrom %d\n", ret);
        #endif
        }
    }

exit:

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("KeyBcast_RunUdp failure: %d\n", ret);
    }
#endif

    KeySocket_Unlisten(KEY_BCAST_PORT);
    KeySocket_Close(&listenfd);
    KeySocket_Delete(&listenfd);

    return ret;
}

int KeyServer_Run(void* heap)
{
    int                 ret = 0;
    KS_SOCKET_T listenfd = KS_SOCKET_T_INIT;
    KS_SOCKET_T connfd = KS_SOCKET_T_INIT;
    WOLFSSL_CTX*        ctx = NULL;
    WOLFSSL*            ssl = NULL;
#ifdef HAVE_NETX
    NX_TCP_SOCKET tcpSock;
#else
    const unsigned long inAddrAny = INADDR_ANY;
#endif
    CmdPacket_t reqPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp;
    int n;

#ifdef HAVE_NETX
    /* Extra lifting for NETX sockets */
    listenfd = &tcpSock;
    connfd = &tcpSock;
#endif

    /* init ctx */
    ret = KeyServer_InitCtx(&ctx, wolfTLSv1_2_server_method_ex, heap);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: KeyServer_InitCtx\n");
    #endif
        goto exit;
    }

    /* create socket */
    ret = KeySocket_CreateTcpSocket(&listenfd);
    if (ret != 0) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: CreateTcpSocket\n");
    #endif
        goto exit;
    }

    /* setup socket listener */
#ifndef HAVE_NETX
    /* nx_tcp_socket_listen() binds the socket, so we shouldn't explicitly
     * bind it first. */
    ret = KeySocket_Bind(listenfd, (const struct in_addr*)&inAddrAny, KEY_SERV_PORT, 0);
#endif
    if (ret == 0) {
        ret = KeySocket_Listen(listenfd, KEY_SERV_PORT, LISTENQ);
    }
    if (ret != 0)
        goto exit;

    /* main loop for accepting and responding to clients */
    gKeyServerRunning = 1;
    while (gKeyServerStop == 0) {
        ret = KeySocket_Accept(listenfd, &connfd, 100);
        if (ret > 0) {
            /* create WOLFSSL object and respond */
            if ((ssl = wolfSSL_new(ctx)) == NULL) {
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("Error: wolfSSL_new\n");
            #endif
                ret = MEMORY_E; goto exit;
            }

            /* set connection context */
        #ifdef HAVE_NETX
            wolfSSL_SetIO_NetX(ssl, connfd, NX_WAIT_FOREVER);
        #else
            ret = wolfSSL_set_fd(ssl, connfd);
            if (ret != SSL_SUCCESS)
                goto exit;
        #endif

            ret = wolfSSL_accept(ssl);
            if (ret != SSL_SUCCESS) {
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("Error: wolfSSL_accept\n");
            #endif
                goto exit;
            }

            XMEMSET(req, 0, sizeof(CmdPacket_t));
            n = wolfSSL_read(ssl, req, sizeof(CmdPacket_t));
            if (n > 0) {
                /* check request */
                ret = KeyReq_Check(&reqPkt, CMD_PKT_PRIVATE);
                if (ret < 0) {
                #if KEY_SERVICE_LOGGING_LEVEL >= 1
                    printf("KeyServer_Run: KeyReq_Check error %d\n", ret);
                #endif
                    goto exit;
                }

                /* get response */
                KeyReq_GetResp(reqPkt.header.type, &resp, &n);

                /* write response */
                if (wolfSSL_write(ssl, resp, n) != n) {
                    ret = wolfSSL_get_error(ssl, 0);
                #if KEY_SERVICE_LOGGING_LEVEL >= 1
                    printf("KeyServer_Run: write error %d\n", ret);
                #endif
                    goto exit;
                }
            }
            if (n < 0) {
                ret = wolfSSL_get_error(ssl, 0);
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("KeyServer_Run: read error %d\n", ret);
            #endif
                goto exit;
            }

            /* closes the connections after responding */
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
            ssl = NULL;
            KeySocket_Close(&connfd);
        }

        ret = KeySocket_Relisten(connfd, listenfd, KEY_SERV_PORT);
        if (ret != 0)
            goto exit;
    }

exit:

    gKeyServerRunning = 0;

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Server failure: %d\n", ret);
    }
#endif

    KeySocket_Unlisten(KEY_SERV_PORT);
    KeySocket_Close(&listenfd);
    KeySocket_Delete(&listenfd);

    /* free up memory used by wolfSSL */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return ret;
}

int KeyServer_SetNewKey(unsigned char* pms, int pmsSz,
    unsigned char* serverRandom, int serverRandomSz,
    unsigned char* clientRandom, int clientRandomSz, void* heap)
{
    return KeyReq_BuildKeyReq_Ex(pms, pmsSz, serverRandom, serverRandomSz,
        clientRandom, clientRandomSz, heap);
}

/* KeyServer_GenNewKey
 */
int KeyServer_GenNewKey(void* heap)
{
    int ret;

    ret = KeyReq_BuildKeyReq(heap);
    if (ret == 0) {
        ret = KeyServer_NewKeyChange(heap);
    }

    return ret;
}

int KeyServer_NewKeyUse(void* heap)
{
    int ret;

    ret = KeyReq_BuildKeyUse(heap);

    if (ret == 0) {
        ret = KeyClient_NetUdpBcast(&gBcastAddr,
            gRespPktLen[CMD_PKT_TYPE_KEY_USE],
            (unsigned char*)gRespPkt[CMD_PKT_TYPE_KEY_USE], 0, NULL);
    }

    return ret;
}

int KeyServer_NewKeyChange(void* heap)
{
    (void)heap;

    return KeyClient_NetUdpBcast(&gBcastAddr,
        gRespPktLen[CMD_PKT_TYPE_KEY_CHG],
        (unsigned char*)gRespPkt[CMD_PKT_TYPE_KEY_CHG], 0, NULL);
}

int KeyServer_IsRunning(void)
{
    return gKeyServerRunning;
}

void KeyServer_Stop(void)
{
    gKeyServerStop = 1;
}



/*----------------------------------------------------------------------------*/
/* Client */
/*----------------------------------------------------------------------------*/

/*
 *psk client set up.
 */
static inline unsigned int KeyClient_PskCb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;

    XSTRNCPY(identity, CLIENT_IDENTITY, id_max_len);

    if (key_max_len > sizeof(g_TlsPsk)) {
        key_max_len = sizeof(g_TlsPsk);
    }
    XMEMCPY(key, g_TlsPsk, key_max_len);

    return key_max_len;
}

/*
 * Handles request / response from server.
 */
static int KeyClient_Perform(WOLFSSL* ssl, int type, unsigned char* msg, int* msgLen)
{
    int ret = 0, n;
    CmdPacket_t reqPkt;
    CmdPacket_t respPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp = (unsigned char*)&respPkt;
    unsigned short size;

    XMEMSET(&reqPkt, 0, sizeof(reqPkt));
    reqPkt.header.version = CMD_PKT_VERSION;
    reqPkt.header.type = type;

    /* write request to the server */
    if (wolfSSL_write(ssl, req, sizeof(reqPkt)) != sizeof(reqPkt)) {
        ret = wolfSSL_get_error(ssl, 0);
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_Perform: Write error %d to Server\n", ret);
    #endif
        return ret;
    }

    /* read response from server */
    if (wolfSSL_read(ssl, resp, sizeof(respPkt)) < 0 ) {
        ret = wolfSSL_get_error(ssl, 0);
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_Perform: Server terminate with error %d!\n", ret);
    #endif
        return ret;
    }

    ato16(respPkt.header.size, &size);

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    /* show response from the server */
    printf("Response: Version %d, Cmd %d, Size %d\n",
            respPkt.header.version, respPkt.header.type, size);
#endif

    /* make sure resposne will fit into buffer */
    n = size;
    if (n > *msgLen) {
        n = *msgLen;
    }

    /* return msg */
    XMEMCPY(msg, respPkt.msg.raw, n);
    *msgLen = size;

    return ret;
}

static int KeyClient_GetNet(const struct in_addr* srvAddr, int reqType,
    unsigned char* msg, int* msgLen, void* heap)
{
    int ret;
#ifdef HAVE_NETX
    NX_TCP_SOCKET realSock;
    KS_SOCKET_T sockfd = &realSock;
#else
    #ifdef WOLFSSL_STATIC_MEMORY
        byte clientMemory[80000];
    #endif
    KS_SOCKET_T sockfd = KS_SOCKET_T_INIT;
#endif
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;

    (void)heap;

    /* create and initialize WOLFSSL_CTX structure for TLS 1.2 only */
#ifndef WOLFSSL_STATIC_MEMORY
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, wolfTLSv1_2_client_method_ex,
            clientMemory, sizeof(clientMemory), 0, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("unable to load static memory and create ctx\n");
    #endif
        goto exit;
    }
#endif

    if (ctx == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("wolfSSL_CTX_new error\n");
    #endif
        ret = MEMORY_E; goto exit;
    }

    /* set up pre shared keys */
    wolfSSL_CTX_set_psk_client_callback(ctx, KeyClient_PskCb);

    /* create socket */
    ret = KeySocket_CreateTcpSocket(&sockfd);
    if (ret != 0) {
        goto exit;
    }

    /* Connect to socket */
    ret = KeySocket_Connect(sockfd, srvAddr, KEY_SERV_PORT);
    if (ret != 0) {
        goto exit;
    }

    /* creat wolfssl object after each tcp connct */
    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("wolfSSL_new error\n");
    #endif
        ret = MEMORY_E; goto exit;
    }

    /* associate the file descriptor with the session */
#ifdef HAVE_NETX
    wolfSSL_SetIO_NetX(ssl, sockfd, NX_WAIT_FOREVER);
#else
    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS)
        goto exit;

#endif

    /* perform request and return response */
    ret = KeyClient_Perform(ssl, reqType, msg, msgLen);
    if (ret != 0)
        goto exit;

exit:

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Client failure: %d\n", ret);
    }
#endif

    wolfSSL_shutdown(ssl);
    KeySocket_Unbind(sockfd);
    KeySocket_Close(&sockfd);
    KeySocket_Delete(&sockfd);

    /* cleanup */
    wolfSSL_free(ssl);

    /* when completely done using SSL/TLS, free the
     * wolfssl_ctx object */
    wolfSSL_CTX_free(ctx);

    return ret;
}

static int KeyClient_NetUdpBcast(const struct in_addr* srvAddr, int txMsgLen,
    unsigned char* txMsg, int* rxMsgLen, unsigned char* rxMsg)
{
    int ret;
#ifdef HAVE_NETX
    NX_UDP_SOCKET realSock;
    KS_SOCKET_T sockfd = (KS_SOCKET_T)&realSock;
    ULONG addr = 0, mask = 0;
#else
    KS_SOCKET_T sockfd = KS_SOCKET_T_INIT;
    struct timeval to = {0, 500000};
#endif
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    int n;

    /* create socket */
    ret = KeySocket_CreateUdpSocket(&sockfd);
    if (ret != 0) {
        goto exit;
    }

    /* enable broadcast */
    KeySocket_SetBroadcast(sockfd);

    /* build broadcast addr */
    XMEMSET(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(KEY_BCAST_PORT);
#ifndef HAVE_NETX
    clientAddr.sin_addr = *srvAddr;
    KeySocket_SetSockOpt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
#else
    (void)srvAddr;
    ret = KeySocket_Bind(sockfd, (const struct in_addr*)&clientAddr.sin_addr,
        KEY_BCAST_PORT, 1);
    if (ret != 0) {
        goto exit;
    }

    /* Derive and set broadcast address. */
    ret = nx_ip_address_get(nxIp, &addr, &mask);
    if (ret != NX_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_NetUdpBcast Error: ip address get %d\n", ret);
    #endif
        ret = -1;
        goto exit;
    }
    clientAddr.sin_addr.s_addr = addr | 0xFF;
#endif

    /* send broadcast */
    ret = KeySocket_SendTo(sockfd, (char*)txMsg, txMsgLen, 0,
        (struct sockaddr*)&clientAddr, clientAddrLen);
    if (ret != txMsgLen) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_NetUdpBcast Error: KeySocket_SendTo %d\n", ret);
    #endif
        ret = -1;
        goto exit;
    }

    /* if we are expecting a response */
    if (rxMsg && *rxMsgLen > 0) {
        /* read response */
        n = KeySocket_RecvFrom(sockfd, (char*)rxMsg, *rxMsgLen, 0,
                                 (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (n <= 0) {
            ret = n;
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("KeyClient_NetUdpBcast: Response error or timeout! %d!\n", ret);
        #endif
            goto exit;
        }

        *rxMsgLen = n;
    }

    ret = 0; /* success */

exit:

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("KeyClient_NetUdpBcast Error: %d\n", ret);
    }
#endif

    KeySocket_CloseUdp(&sockfd);

    return ret;
}

static int KeyClient_GetNetUdp(const struct in_addr* srvAddr, int reqType,
    unsigned char* msg, int* msgLen, void* heap)
{
    int ret;
    CmdPacket_t* pkt;
    unsigned short size;
    int n;

    (void)heap;

    /* build request */
    ret = BuildPacket(&pkt, reqType, 0, NULL, heap);
    if (ret != 0)
        return ret;

    /* send request and get msg */
    ret = KeyClient_NetUdpBcast(srvAddr,
        sizeof(CmdHeader_t), (unsigned char*)&pkt,
        msgLen, (unsigned char*)&pkt);
    if (ret < 0) {
        return ret;
    }

    /* parse response */
    ato16(pkt->header.size, &size);

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    /* show response from the server */
    printf("Response: Version %d, Cmd %d, Size %d\n",
            pkt->header.version, pkt->header.type, size);
#endif

    /* make sure response will fit into buffer */
    n = size;
    if (msgLen && n > *msgLen) {
        n = *msgLen;
    }

    /* return msg */
    if (msg)
        XMEMCPY(msg, pkt->msg.raw, n);
    if (msgLen)
        *msgLen = n;

    ret = 0; /* success */

    return ret;
}

#ifndef KEY_SERVICE_FORCE_CLIENT_TO_USE_NET
static int KeyClient_GetLocal(int reqType, unsigned char* msg, int* msgLen,
    void* heap)
{
    int ret;
    unsigned char* resp;
    int n;
    CmdPacket_t* respPkt;
    CmdPacket_t reqPkt;
    unsigned short size;

    XMEMSET(&reqPkt, 0, sizeof(reqPkt));
    reqPkt.header.version = CMD_PKT_VERSION;
    reqPkt.header.type = reqType;

    /* check request */
    ret = KeyReq_Check(&reqPkt, CMD_PKT_PRIVATE);
    if (ret < 0) {
        return ret;
    }

    KeyReq_GetResp(reqType, &resp, &n);
    respPkt = (CmdPacket_t*)resp;
    ato16(respPkt->header.size, &size);

    /* return only length provided */
    if (size > n - sizeof(CmdHeader_t))
        size = n - sizeof(CmdHeader_t);
    if (msgLen && size > *msgLen)
        size = *msgLen;

    if (msg)
        XMEMCPY(msg, respPkt->msg.raw, size);
    if (msgLen)
        *msgLen = size;

    (void)heap;

    return ret;
}
#endif


int KeyClient_Get(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap)
{
    int ret;

#ifndef KEY_SERVICE_FORCE_CLIENT_TO_USE_NET
    /* check to see if server is running locally */
    if (gKeyServerInitDone) {
        ret = KeyClient_GetLocal(reqType, msg, msgLen, heap);
    }
    else
#endif
    {
        ret = KeyClient_GetNet(srvAddr, reqType, msg, msgLen, heap);
    }

    return ret;
}

int KeyClient_GetUdp(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap)
{
    int ret;

#ifndef KEY_SERVICE_FORCE_CLIENT_TO_USE_NET
    /* check to see if server is running locally */
    if (gKeyServerInitDone) {
        ret = KeyClient_GetLocal(reqType, msg, msgLen, heap);
    }
    else
#endif
    {
        ret = KeyClient_GetNetUdp(srvAddr, reqType, msg, msgLen, heap);
    }

    return ret;
}

int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap)
{
    int msgLen = sizeof(KeyRespPacket_t);
    return KeyClient_Get(srvAddr, CMD_PKT_TYPE_KEY_REQ, (unsigned char*)keyResp, &msgLen, heap);
}


int KeyClient_FindMaster(struct in_addr* srvAddr, void* heap)
{
    int msgLen = sizeof(AddrRespPacket_t);
    return KeyClient_GetUdp(srvAddr, CMD_PKT_TYPE_DISCOVER, (unsigned char*)srvAddr, &msgLen, heap);
}

int KeyClient_NewKeyRequest(const struct in_addr* srvAddr, EpochRespPacket_t* epochResp, void* heap)
{
    int msgLen = sizeof(EpochRespPacket_t);
    return KeyClient_GetNet(srvAddr, CMD_PKT_TYPE_KEY_NEW, (unsigned char*)epochResp, &msgLen, heap);
}

void KeyBcast_DefaultCb(CmdPacket_t* pkt)
{
    if (pkt) {
        switch (pkt->header.type) {
            case CMD_PKT_TYPE_KEY_CHG:
                #if KEY_SERVICE_LOGGING_LEVEL >= 2
                    printf("Bcast Callback: New Key Available\n");
                #endif
                break;
            case CMD_PKT_TYPE_KEY_USE:
                #if KEY_SERVICE_LOGGING_LEVEL >= 2
                    printf("Bcast Callback: Use New Key\n");
                #endif
                break;
            case CMD_PKT_TYPE_DISCOVER:
                #if KEY_SERVICE_LOGGING_LEVEL >= 2
                    printf("Bcast Callback: Discover\n");
                #endif
                break;
            default:
                #if KEY_SERVICE_LOGGING_LEVEL >= 1
                    printf("Bcast Callback: Unsupported packet type %u\n",
                        pkt->header.type);
                #endif
                break;
        }
    }
}
