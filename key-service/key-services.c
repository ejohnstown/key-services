#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "key-services.h"

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#define KEY_SERVICE_LOGGING_LEVEL   2

#define KEY_SERVICE_FORCE_CLIENT_TO_USE_NET /* for testing */
#ifdef HAVE_NETX
    #define printf bsp_debug_printf
    extern NX_IP *nxIp;
#endif

/*----------------------------------------------------------------------------*/
/* Server */
/*----------------------------------------------------------------------------*/

/* Generic responses for all supported packet types */
static CmdRespPacket_t* gRespPkt;
static int gKeyServerInitDone = 0;
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

static int KeyReq_Build(void* heap)
{
    int ret;
    WC_RNG rng;
    const int type = CMD_PKT_TYPE_KEY_REQ;

    /* get random data for key */
    ret = wc_InitRng_ex(&rng, heap);
    if (ret == 0) {
        CmdRespPacket_t* resp = &gRespPkt[type-1];

        ret = wc_RNG_GenerateBlock(&rng, resp->msg, MAX_PACKET_MSG);
        if (ret == 0) {
            /* populate generic response packet */
            resp->header.version = CMD_PKT_VERSION;
            resp->header.type = CMD_PKT_TYPE_KEY_REQ;
            c16toa(MAX_PACKET_MSG, resp->header.size);
            c16toa(++gKeyServerEpoch, resp->keyResp.epoch);
            resp->keyResp.suite[0] = CIPHER_SUITE_0;
            resp->keyResp.suite[1] = CIPHER_SUITE_1;
        }

        wc_FreeRng(&rng);
    }

    return ret;
}

static void KeyReq_GetResp(int type, unsigned char** resp, int* respLen)
{
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

/*
 * Handles request / response to client.
 */
static int KeyServer_Perform(WOLFSSL* ssl)
{
    int ret = 0;
    CmdReqPacket_t reqPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp;
    int n;

    XMEMSET(req, 0, sizeof(CmdReqPacket_t));
    n = wolfSSL_read(ssl, req, sizeof(CmdReqPacket_t));
    if (n > 0) {
        /* check request */
        ret = KeyReq_Check(&reqPkt);
        if (ret != 0) {
            return ret;
        }

        /* get response */
        KeyReq_GetResp(reqPkt.header.type, &resp, &n);

        /* write response */
        if (wolfSSL_write(ssl, resp, n) != n) {
            ret = wolfSSL_get_error(ssl, 0);
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("KeyServer_Perform: write error %d\n", ret);
        #endif
            return ret;
        }
    }
    if (n < 0) {
        ret = wolfSSL_get_error(ssl, 0);
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyServer_Perform: read error %d\n", ret);
    #endif
        return ret;
    }

    return ret;
}

static int KeyServer_Init(void* heap)
{
    int ret = 0;

    if (gKeyServerInitDone == 0) {
        gRespPkt = (CmdRespPacket_t*)XMALLOC(
                        sizeof(CmdRespPacket_t) * (CMD_PKT_TYPE_COUNT-1),
                        heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (gRespPkt == NULL) {
            return MEMORY_E;
        }

        /* init each command type */
        ret = KeyReq_Build(heap);

        gKeyServerInitDone = 1;
    }

    return ret;
}

static void KeyServer_Free(void* heap)
{
    XFREE(gRespPkt, heap, DYNAMIC_TYPE_TMP_BUFFER);
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
#else
    const unsigned long inAddrAny = INADDR_ANY;
#endif
    int keyFlag = 0;

    /* generate response(s) */
    ret = KeyServer_Init(heap);
    if (ret != 0)
        goto exit;

    /* create and initialize WOLFSSL_CTX structure for TLS 1.2 only */
#ifndef WOLFSSL_STATIC_MEMORY
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, wolfTLSv1_2_server_method_ex,
            serverMemory, sizeof(serverMemory), 0, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: unable to load static memory and create ctx\n");
    #endif
        goto exit;
    }

    /* load in a buffer for IO */
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, NULL, serverMemoryIO, sizeof(serverMemoryIO),
            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: unable to load static IO memory and create ctx\n");
    #endif
        goto exit;
    }
#endif
    if (ctx == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: wolfSSL_CTX_new error\n");
    #endif
        ret = MEMORY_E; goto exit;
    }

    /* use psk suite for security */
    wolfSSL_CTX_set_psk_server_callback(ctx, KeyServer_PskCb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, SERVER_IDENTITY);
    if (wolfSSL_CTX_set_cipher_list(ctx, PSK_CIPHER_SUITE)
                                   != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: server can't set cipher list\n");
    #endif
        ret = -1; goto exit;
    }

    /* create socket */
    ret = KeySocket_CreateTcpSocket(&listenfd);
    if (ret != 0) {
        goto exit;
    }

    /* setup socket listener */
#ifdef HAVE_NETX
    ret = (int)nx_tcp_server_socket_listen(nxIp, SERV_PORT, listenfd, LISTENQ, NULL);
    if (ret != NX_SUCCESS) {
        printf("Error: cannot listen to the socket. (%d)\n", ret);
        goto exit;
    }
#else
    ret = KeySocket_Bind(listenfd, (const struct in_addr*)&inAddrAny, SERV_PORT);
    if (ret == 0) {
        ret = KeySocket_Listen(listenfd, SERV_PORT, LISTENQ);
    }
    if (ret != 0)
        goto exit;
#endif

    /* main loop for accepting and responding to clients */
    gKeyServerRunning = 1;
    while (gKeyServerStop == 0) {
#ifdef HAVE_NETX
        ret = (int)nx_tcp_server_socket_accept(listenfd, NX_WAIT_FOREVER);
        if (ret == NX_SUCCESS) ret = 1;
#else
        ret = KeySocket_Accept(listenfd, &connfd, 100);
#endif
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

            ret = KeyServer_Perform(ssl);
            if (ret != 0)
                goto exit;

            /* closes the connections after responding */
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
#ifdef HAVE_NETX
            nx_tcp_socket_disconnect(connfd, NX_NO_WAIT);
#else
            KeySocket_Close(&connfd);
#endif
            /* XXX Hack to force updates. Check against 2 if adding the linux peer */
            if (keyFlag == 1) {
                gKeyServerInitDone = 0;
                printf("Updating the key.\n");
                KeyServer_Init(heap);
                keyFlag = 0;
            }
            else
                keyFlag++;
        }
#ifdef HAVE_NETX
        ret = nx_tcp_server_socket_unaccept(connfd);
        if (ret != NX_SUCCESS)
            goto exit;
        ret = nx_tcp_server_socket_relisten(nxIp, SERV_PORT, listenfd);
        if (ret != NX_SUCCESS)
            goto exit;
#endif
    }

exit:

    gKeyServerRunning = 0;

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Server failure: %d\n", ret);
    }
#endif

#ifdef HAVE_NETX
    nx_tcp_server_socket_unlisten(nxIp, SERV_PORT);
    nx_tcp_socket_delete(listenfd);
#else
    KeySocket_Close(&listenfd);
#endif

    /* free up memory used by wolfSSL */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    KeyServer_Free(heap);

    return ret;
}

int KeyServer_SetNewKey(void* heap)
{
    return 0;
}

/* KeyServer_GenNewKey
 */
int KeyServer_GenNewKey(void* heap)
{
    return KeyReq_Build(heap);
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
    XMEMCPY(msg, respPkt.msg, n);
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
    ret = KeySocket_Connect(sockfd, srvAddr, SERV_PORT);
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

int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap)
{
    int msgLen = sizeof(KeyRespPacket_t);
    return KeyClient_Get(srvAddr, CMD_PKT_TYPE_KEY_REQ, (unsigned char*)keyResp, &msgLen, heap);
}
