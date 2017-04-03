#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "key-services.h"

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#define KEY_SERVICE_LOGGING_LEVEL   2

#define KEY_SERVICE_FORCE_CLIENT_TO_USE_NET /* for testing */

//#define TEST_KEY_ROLL

#ifdef HAVE_NETX
    #define printf bsp_debug_printf
    extern NX_IP *nxIp;
#endif

/*----------------------------------------------------------------------------*/
/* Server */
/*----------------------------------------------------------------------------*/

/* Generic responses for all supported packet types */
static CmdRespPacket_t* gRespPkt;
static volatile int gKeyServerInitDone = 0;
static int gKeyServerRunning = 0;
static int gKeyServerStop = 0;
static unsigned short gKeyServerEpoch;

#ifdef WOLFSSL_STATIC_MEMORY
    #ifdef HAVE_NETX
        static byte clientMemory[80000];
        static byte clientMemoryIO[34500];
    #endif
    static byte serverMemory[80000];
    static byte serverMemoryIO[34500];
#endif

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

static int KeyReq_BuildKeyReq_Ex(unsigned char* pms, int pmsSz,
    unsigned char* serverRandom, int serverRandomSz,
    unsigned char* clientRandom, int clientRandomSz, void* heap)
{
    int ret = 0;
    WC_RNG rng;
    const int type = CMD_PKT_TYPE_KEY_REQ;
    CmdRespPacket_t* resp = &gRespPkt[type-1];

    /* get random data for message bytes */
    ret = wc_InitRng_ex(&rng, heap);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, resp->msg.raw, MAX_PACKET_MSG);
        if (ret != 0) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("RNG generate block failed!\n");
        #endif
        }

        wc_FreeRng(&rng);
    }

    if (ret == 0) {
        /* populate generic response packet */
        resp->header.version = CMD_PKT_VERSION;
        resp->header.type = type;
        c16toa(MAX_PACKET_MSG, resp->header.size);
        c16toa(++gKeyServerEpoch, resp->msg.keyResp.epoch);
        resp->msg.keyResp.suite[0] = CIPHER_SUITE_0;
        resp->msg.keyResp.suite[1] = CIPHER_SUITE_1;

        /* use args if provided */
        if (pms) {
            if (pmsSz > PMS_SIZE) pmsSz = PMS_SIZE;
            XMEMCPY(resp->msg.keyResp.pms, pms, pmsSz);
        }
        if (serverRandom) {
            if (serverRandomSz > RAND_SIZE) serverRandomSz = RAND_SIZE;
            XMEMCPY(resp->msg.keyResp.serverRandom, serverRandom, serverRandomSz);
        }
        if (clientRandom) {
            if (clientRandomSz > RAND_SIZE) clientRandomSz = RAND_SIZE;
            XMEMCPY(resp->msg.keyResp.clientRandom, clientRandom, clientRandomSz);
        }
    }

    return ret;
}

static int KeyReq_BuildDiscover(void)
{
    int ret = 0;
    const int type = CMD_PKT_TYPE_DISCOVER;
    CmdRespPacket_t* resp = &gRespPkt[type-1];
    const unsigned char ipaddr[4] = {KEY_SERV_LOCAL_ADDR};
    int ipaddrSz = sizeof(ipaddr);

    /* populate generic response packet */
    resp->header.version = CMD_PKT_VERSION;
    resp->header.type = type;
    c16toa(ipaddrSz, resp->header.size);
    XMEMCPY(resp->msg.discResp.ipaddr, ipaddr, ipaddrSz);

    return ret;
}

static int KeyReq_BuildKeyReq(void* heap)
{
    return KeyReq_BuildKeyReq_Ex(NULL, 0, NULL, 0, NULL, 0, heap);
}

static void KeyReq_GetResp(int type, unsigned char** resp, int* respLen)
{
    if (resp)
        *resp = NULL;
    if (respLen)
        *respLen = 0;

    /* check for valid type */
    if (type >= CMD_PKT_TYPE_COUNT || type <= CMD_PKT_TYPE_INVALID)
        return;

    /* calculate and return packet size */
    if (respLen) {
        unsigned short size;
        ato16(gRespPkt[type-1].header.size, &size);
        *respLen = size + sizeof(CmdPacketHeader_t);
    }

    /* return buffer to response */
    if (resp)
        *resp = (unsigned char*)&gRespPkt[type-1];
}

static int KeyReq_Check(CmdReqPacket_t* reqPkt)
{
    int ret = 0;

    if (reqPkt == NULL) {
        return BAD_FUNC_ARG;
    }

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    {
        unsigned short size;
        ato16(reqPkt->header.size, &size);
        printf("Request: Version %d, Cmd %d, Size %d\n",
            reqPkt->header.version, reqPkt->header.type, size);
    }
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

    return ret;
}

int KeyServer_Init(void* heap)
{
    int ret = 0;

    if (++gKeyServerInitDone == 1) {
        gRespPkt = (CmdRespPacket_t*)XMALLOC(
                        sizeof(CmdRespPacket_t) * (CMD_PKT_TYPE_COUNT-1),
                        heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (gRespPkt == NULL) {
            return MEMORY_E;
        }

        /* init each command type */
        ret = KeyReq_BuildKeyReq(heap);
        if (ret != 0)
            return ret;

        ret = KeyReq_BuildDiscover();
    }

    return ret;
}

void KeyServer_Free(void* heap)
{
    if (--gKeyServerInitDone == 0) {
        XFREE(gRespPkt, heap, DYNAMIC_TYPE_TMP_BUFFER);
        gRespPkt = NULL;
    }
}

static int KeyServer_InitCtx(WOLFSSL_CTX** pCtx, wolfSSL_method_func method_func, void* heap)
{
    int ret = 0;
    WOLFSSL_CTX* ctx;

    /* init the WOLFSSL_CTX */
    /* create and initialize WOLFSSL_CTX structure for TLS 1.2 only */
#ifndef WOLFSSL_STATIC_MEMORY
    WOLFSSL_METHOD* method = method_func(heap);
    ctx = wolfSSL_CTX_new(method);
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, method_func,
            serverMemory, sizeof(serverMemory), 0, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: unable to load static memory and create ctx\n");
    #endif
    }
    else {
        /* load in a buffer for IO */
        ret = wolfSSL_CTX_load_static_memory(
                &ctx, NULL, serverMemoryIO, sizeof(serverMemoryIO),
                WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
        if (ret != SSL_SUCCESS) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("Error: unable to load static IO memory and create ctx\n");
        #endif
        }
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

int KeyServer_RunUdp(void* heap)
{
    int                 ret = 0;
    KS_SOCKET_T listenfd = KS_SOCKET_T_INIT;
    const unsigned long inAddrAny = INADDR_ANY;
    int opt = 1, n;
    CmdReqPacket_t reqPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp;
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen;

    /* create socket */
    ret = KeySocket_CreateUdpSocket(&listenfd);
    if (ret != 0) {
        goto exit;
    }

    /* setup socket as non-blocking */
    KeySocket_SetNonBlocking(listenfd);

    /* enable broadcast */
    KeySocket_SetSockOpt(listenfd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

    /* setup socket listener */
    ret = KeySocket_Bind(listenfd, (const struct in_addr*)&inAddrAny, KEY_BCAST_PORT);
    if (ret != 0)
        goto exit;

    /* main loop for accepting and responding to clients */
    while (gKeyServerStop == 0) {
        /* wait for client */
        clientAddrLen = sizeof(clientAddr);

        XMEMSET(req, 0, sizeof(CmdReqPacket_t));
        ret = KeySocket_RecvFrom(listenfd, (char*)req, sizeof(CmdReqPacket_t),
            0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (ret > 0) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 2
            unsigned char* addr = (unsigned char*)&clientAddr.sin_addr.s_addr;
            printf("Recieved Bcast from: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
        #endif
            /* check request */
            ret = KeyReq_Check(&reqPkt);
            if (ret != 0) {
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("KeyServer_RunUdp Error: KeyReq_Check failed %d\n", ret);
            #endif
                continue;
            }

            /* get response */
            KeyReq_GetResp(reqPkt.header.type, &resp, &n);

            /* write response */
            ret = KeySocket_SendTo(listenfd, (char*)resp, n, 0,
                (struct sockaddr*)&clientAddr, clientAddrLen);
            if (ret != n) {
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("KeyServer_RunUdp Error: SendTo %d\n", ret);
            #endif
                continue;
            }
        }
        else if (ret == WOLFSSL_CBIO_ERR_WANT_READ) {
            /* no data (EAGAIN) */
            sleep(1);
            ret = 0;
        }
        else if (ret < 0) {
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("KeyServer_RunUdp Error: RecvFrom %d\n", ret);
        #endif
        }
    }

exit:

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Server UDP failure: %d\n", ret);
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

    /* Extra lifting for NETX sockets */
    listenfd = &tcpSock;
    connfd = &tcpSock;
#endif
    const unsigned long inAddrAny = INADDR_ANY;
    CmdReqPacket_t reqPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp;
    int n;
#ifdef TEST_KEY_ROLL
    int keyFlag = 0;
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
    ret = KeySocket_Bind(listenfd, (const struct in_addr*)&inAddrAny, KEY_SERV_PORT);
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

            XMEMSET(req, 0, sizeof(CmdReqPacket_t));
            n = wolfSSL_read(ssl, req, sizeof(CmdReqPacket_t));
            if (n > 0) {
                /* check request */
                ret = KeyReq_Check(&reqPkt);
                if (ret != 0) {
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

        #ifdef TEST_KEY_ROLL
            /* XXX Hack to force updates. Check against 2 if adding the linux peer */
            if (keyFlag == 1) {
                gKeyServerInitDone = 0;
                printf("Updating the key.\n");
                KeyServer_GenNewKey(heap);
                keyFlag = 0;
            }
            else
                keyFlag++;
        #endif
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
    return KeyReq_BuildKeyReq(heap);
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
    CmdReqPacket_t reqPkt;
    CmdRespPacket_t respPkt;
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
    KS_SOCKET_T sockfd = KS_SOCKET_T_INIT;
#ifdef WOLFSSL_STATIC_MEMORY
    byte clientMemory[80000];
    byte clientMemoryIO[34500];
#endif
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

    /* load in a buffer for IO */
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, NULL, clientMemoryIO, sizeof(clientMemoryIO),
            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("unable to load static IO memory and create ctx\n");
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
    KeySocket_Close(&sockfd);

    /* cleanup */
    wolfSSL_free(ssl);

    /* when completely done using SSL/TLS, free the
     * wolfssl_ctx object */
    wolfSSL_CTX_free(ctx);

    return ret;
}

static int KeyClient_GetNetUdp(const struct in_addr* srvAddr, int reqType,
    unsigned char* msg, int* msgLen, void* heap)
{
    int ret;
#ifdef HAVE_NETX
    NX_TCP_SOCKET realSock;
    KS_SOCKET_T sockfd = &realSock;
#else
    KS_SOCKET_T sockfd = KS_SOCKET_T_INIT;
#endif
    CmdReqPacket_t reqPkt;
    CmdRespPacket_t respPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp = (unsigned char*)&respPkt;
    unsigned short size;
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    int opt = 1, n;

    (void)heap;

    /* create socket */
    ret = KeySocket_CreateUdpSocket(&sockfd);
    if (ret != 0) {
        goto exit;
    }

    /* enable broadcast */
    KeySocket_SetSockOpt(sockfd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

    /* build request */
    XMEMSET(&reqPkt, 0, sizeof(reqPkt));
    reqPkt.header.version = CMD_PKT_VERSION;
    reqPkt.header.type = reqType;

    /* build broadcast addr */
    XMEMSET(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;;
    clientAddr.sin_port = htons(KEY_BCAST_PORT);
    clientAddr.sin_addr = *srvAddr;

    /* send broadcast */
    ret = KeySocket_SendTo(sockfd, (char*)req, sizeof(reqPkt), 0,
        (struct sockaddr*)&clientAddr, clientAddrLen);
    if (ret != sizeof(reqPkt)) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_GetNetUdp Error: KeySocket_SendTo %d\n", ret);
    #endif
        ret = -1;
        goto exit;
    }

    /* read response */
    n = KeySocket_RecvFrom(sockfd, (char*)resp, sizeof(respPkt), 0,
                             (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (n <= 0) {
        ret = n;
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_GetNetUdp: Response error or timeout! %d!\n", ret);
    #endif
        goto exit;
    }

    ato16(respPkt.header.size, &size);

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    /* show response from the server */
    printf("Response: Version %d, Cmd %d, Size %d\n",
            respPkt.header.version, respPkt.header.type, size);
#endif

    /* make sure resposne will fit into buffer */
    n = size;
    if (msgLen && n > *msgLen) {
        n = *msgLen;
    }

    /* return msg */
    if (msg)
        XMEMCPY(msg, respPkt.msg.raw, n);
    if (msgLen)
        *msgLen = size;

    ret = 0; /* success */

exit:

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Client failure: %d\n", ret);
    }
#endif

    KeySocket_Close(&sockfd);

    return ret;
}

#ifndef KEY_SERVICE_FORCE_CLIENT_TO_USE_NET
static int KeyClient_GetLocal(int reqType, unsigned char* msg, int* msgLen,
    void* heap)
{
    int ret;
    unsigned char* resp;
    int n;
    CmdReqPacket_t reqPkt;

    XMEMSET(&reqPkt, 0, sizeof(reqPkt));
    reqPkt.header.version = CMD_PKT_VERSION;
    reqPkt.header.type = reqType;

    /* check request */
    ret = KeyReq_Check(&reqPkt);
    if (ret != 0) {
        return ret;
    }

    KeyReq_GetResp(reqType, &resp, &n);

    /* return only length provided */
    if (n > *msgLen)
        n = *msgLen;

    memcpy(msg, resp, n);

    *msgLen = n;

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
    int msgLen = sizeof(DiscRespPacket_t);
    return KeyClient_GetUdp(srvAddr, CMD_PKT_TYPE_DISCOVER, (unsigned char*)srvAddr, &msgLen, heap);
}
