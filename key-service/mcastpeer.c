/* mcastpeer.c */

/*
 gcc -Wall mcastpeer.c -o ./mcastpeer -lwolfssl

*/

/* handles wolfSSL and socket includes */
#include "key-services.h"

#ifndef NETX
/* additional *nix headers needed for threading, select and time */
    #include <sys/select.h>
    #include <sys/time.h>
    #include <pthread.h>
#endif

/* configration */
#define KEY_SERVER_IP       IP_ADDRESS(127,0,0,1)
#define GROUP_ADDR          IP_ADDRESS(226,0,0,3)
#define GROUP_PORT          12345
#define MSG_SIZE            sizeof(KeyRespPacket_t)
#define STATUS_INVERVAL_MS  20 /* 50Hz */

//#define ENABLE_MSG_DEBUG
#ifndef HAVE_SIGNAL
    #define HAVE_SIGNAL 1
#endif

typedef struct PeerInfo {
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    pthread_t threadId;
    unsigned short id;
    char msg[MSG_SIZE];
    KS_SOCKET_T rxfd;
    KS_SOCKET_T txfd;
    int ret;

    int rxCount;
    int txCount;
    int elapsedMs;
} PeerInfo_t;

static int gPeerThreads;
static PeerInfo_t* gPeers;
static int gStopPeers = 0;
static const struct in_addr gKeySrvAddr = { .s_addr = KEY_SERVER_IP };
static const struct in_addr gGroupAddr = { .s_addr = GROUP_ADDR };
static const struct in_addr gAnyAddr = { .s_addr = INADDR_ANY };

static int seq_cb(word16 peerId, word32 maxSeq, word32 curSeq, void* ctx)
{
#ifdef ENABLE_MSG_DEBUG
    char* ctxStr = (char*)ctx;
    printf("Highwater Callback (%u:%u/%u): %s\n", peerId, curSeq, maxSeq,
          ctxStr != NULL ? ctxStr : "Forgot to set the callback context.");
#endif

    return 0;
}

int PeerSendStatus(PeerInfo_t* peer)
{
    int ret = 0, n;
    size_t msg_len;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    sprintf(peer->msg, "time: %d.%06d\n", (int)tv.tv_sec, (int)tv.tv_usec);
#ifdef ENABLE_MSG_DEBUG
    printf("sending msg: %s\n", msg);
#endif
    msg_len = strlen(peer->msg) + 1; /* include null */

    n = wolfSSL_write(peer->ssl, peer->msg, (unsigned int)msg_len);
    if (n < 0) {
        n = wolfSSL_get_error(peer->ssl, n);
        fprintf(stderr, "wolfSSL_write error: %s (%d)\n",
                wolfSSL_ERR_reason_error_string(n), n);
        exit(EXIT_FAILURE);
    }
    peer->txCount++;

    return ret;
}

static int GetElapsedMs(struct timeval* start, struct timeval* end)
{
    long secs_used, micros_used;
    secs_used = (end->tv_sec - start->tv_sec); // avoid overflow by subtracting first
    micros_used = ((secs_used * 1000000) + end->tv_usec) - start->tv_usec;
    return (int)(micros_used / 1000);
}

int PeerReadStatus(PeerInfo_t* peer, int timeoutMs)
{
    int ret = 0, n;
    struct timeval start, end;
    unsigned short peerId;

    gettimeofday(&start, NULL);

    /* perform read for timeoutMs duration */
    while (1) {

        ret = KeySocket_Select(peer->rxfd, timeoutMs);
        if (ret > 0) {
            n = wolfSSL_mcast_read(peer->ssl, &peerId, peer->msg, sizeof(peer->msg));
            if (n < 0) {
                n = wolfSSL_get_error(peer->ssl, n);
                if (n != SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "recvfrom error: %s\n",
                            wolfSSL_ERR_reason_error_string(n));
                    ret = -1;
                    break;
                }
            }
            else {
                peer->rxCount++;
            #ifdef ENABLE_MSG_DEBUG
                printf("got msg from peer %u %s\n", peerId, peer->msg);
            #endif
            }

            /* calculate new timeout */
            gettimeofday(&end, NULL);
            timeoutMs -= GetElapsedMs(&start, &end);
            if (timeoutMs <= 0) {
                ret = 0;
                break;
            }
        }
        else {
            /* timeout done */
            ret = 0;
            break;
        }
    }

    return ret;
}

/* simulates activity that would occur on a peer */
static void* PeerThread(void* arg)
{
    PeerInfo_t* peer = (PeerInfo_t*)arg;
    int ret = 0, i;
    struct sockaddr_in txAddr;
    const char seqHwCbCtx[] = "Callback context string.";
    KeyRespPacket_t* keyResp;
    const unsigned char suite[2] = {0, 0xFE};  /* WDM_WITH_NULL_SHA256 */
    struct timeval start, end;
    void* heap = NULL;
#ifdef WOLFSSL_STATIC_MEMORY
    byte memory[80000];
    byte memoryIO[34500];
#endif

    gettimeofday(&start, NULL);

    /* use peer msg buffer for key response info */
    keyResp = (KeyRespPacket_t*)peer->msg;

    /* Get PMS, Server/Client Random from Key Server */
    ret = KeyClient_GetKey(&gKeySrvAddr, keyResp, heap);
    if (ret != 0) {
        printf("unable to get key from server\n");

        /* continue anyway for testing, using pre-determined values */
        memset(keyResp->pms, 0x23, sizeof(keyResp->pms));
        memset(keyResp->clientRandom, 0xA5, sizeof(keyResp->clientRandom));
        memset(keyResp->serverRandom, 0x5A, sizeof(keyResp->serverRandom));
    }

    /* Setup the multicast sockets */
    ret = KeySocket_CreateUdpSocket(&peer->rxfd);
    if (ret < 0) {
        perror("create rx socket failed");
        goto exit;
    }

    ret = KeySocket_CreateUdpSocket(&peer->txfd);
    if (ret < 0) {
        perror("create tx socket failed");
        goto exit;
    }

    ret = KeySocket_Bind(peer->rxfd, &gAnyAddr, GROUP_PORT);
    if (ret < 0) {
        perror("rx bind failed");
        goto exit;
    }

    ret = KeySocket_SetIpMembership(peer->rxfd, &gGroupAddr, &gAnyAddr);
    if (ret < 0) {
        perror("setsockopt mc add membership failed");
        goto exit;
    }

    /* setup RX socket as non-blocking */
    KeySocket_SetNonBlocking(peer->rxfd);

    /* Create wolfSSL instance for DTLS Multicast */
#ifndef WOLFSSL_STATIC_MEMORY
    peer->ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &peer->ctx, wolfDTLSv1_2_client_method_ex,
            memory, sizeof(memory), 0, 1);
    if (ret != SSL_SUCCESS) {
        printf("unable to load static memory and create ctx\n");
        goto exit;
    }

    /* load in a buffer for IO */
    ret = wolfSSL_CTX_load_static_memory(
            &peer->ctx, NULL, memoryIO, sizeof(memoryIO),
            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
    if (ret != SSL_SUCCESS) {
        printf("unable to load static IO memory and create ctx\n");
        goto exit;
    }
#endif
    if (!peer->ctx) {
        printf("ctx new error");
        ret = MEMORY_E; goto exit;
    }

    ret = wolfSSL_CTX_mcast_set_member_id(peer->ctx, peer->id);
    if (ret != SSL_SUCCESS) {
        printf("set mcast member id error\n");
        goto exit;
    }

    ret = wolfSSL_CTX_mcast_set_highwater_cb(peer->ctx, 100, 10, 20, seq_cb);
    if (ret != SSL_SUCCESS) {
        printf("set mcast highwater cb error\n");
        goto exit;
    }

    peer->ssl = wolfSSL_new(peer->ctx);
    if (!peer->ssl) {
        printf("ssl new error\n");
        ret = MEMORY_E; goto exit;
    }

    ret = wolfSSL_set_read_fd(peer->ssl, peer->rxfd);
    if (ret != SSL_SUCCESS) {
        printf("set ssl read fd error\n");
        goto exit;
    }

    ret = wolfSSL_set_write_fd(peer->ssl, peer->txfd);
    if (ret != SSL_SUCCESS) {
        printf("set ssl write fd error\n");
        goto exit;
    }

    memset(&txAddr, 0, sizeof(txAddr));
    txAddr.sin_family = AF_INET;
    txAddr.sin_addr.s_addr = gGroupAddr.s_addr;
    txAddr.sin_port = htons(GROUP_PORT);

    ret = wolfSSL_dtls_set_peer(peer->ssl, &txAddr, sizeof(txAddr));
    if (ret != SSL_SUCCESS) {
        printf("set ssl sender error\n");
        goto exit;
    }

    ret = wolfSSL_mcast_set_highwater_ctx(peer->ssl, (char*)seqHwCbCtx);
    if (ret != SSL_SUCCESS) {
        printf("set highwater ctx error\n");
        goto exit;
    }

    /* add all peers to list */
    for (i = 0; i < gPeerThreads; i++) {
        ret = wolfSSL_mcast_peer_add(peer->ssl, i, 0);
        if (ret != SSL_SUCCESS) {
            printf("mcast add peer error\n");
            goto exit;
        }
    }

    wolfSSL_set_using_nonblock(peer->ssl, 1);

    ret = wolfSSL_set_secret(peer->ssl, 1, keyResp->pms, sizeof(keyResp->pms),
        keyResp->clientRandom, keyResp->serverRandom, suite);
    if (ret != SSL_SUCCESS) printf("cannot set ssl secret error\n");

    while (gStopPeers == 0) {
        /* send status */
        ret = PeerSendStatus(peer);
        if (ret != 0) {
            printf("Peer send status failed! Error %d\n", ret);
            break;
        }

        /* read status for specified interval */
        ret = PeerReadStatus(peer, STATUS_INVERVAL_MS);
        if (ret != 0) {
            printf("Peer read status failed! Error %d\n", ret);
            break;
        }
    }

exit:

    wolfSSL_free(peer->ssl);
    wolfSSL_CTX_free(peer->ctx);

    KeySocket_Close(&peer->rxfd);
    KeySocket_Close(&peer->txfd);

    peer->ret = ret;
    gettimeofday(&end, NULL);
    peer->elapsedMs = GetElapsedMs(&start, &end);

    printf("Peer %d: Ret %d, Elapsed %d ms, TX %d, RX %d\n",
                peer->id, peer->ret, peer->elapsedMs, peer->txCount, peer->rxCount);

    return NULL;
}

static void* KeyServerThread(void* arg)
{
    void* heap = arg;
    KeyServer_Run(heap);
    return NULL;
}

static int KeyServerStart(pthread_t* tid)
{
    int ret = 0;

    /* start key server */
    ret = pthread_create(tid, NULL, KeyServerThread, NULL);
    if (ret < 0) {
        perror("key server pthread_create failed");
        return ret;
    }

    /* wait for key server to start */
    while (!KeyServer_IsRunning()) {
        //sleep(1);
    }

    return ret;
}

static int StartPeers(int peerThreads)
{
    int ret = 0;
    int i, maxPeers;
    PeerInfo_t* peer;

    /* check for max peers */
    maxPeers = wolfSSL_mcast_get_max_peers();
    if (peerThreads > maxPeers)
        peerThreads = maxPeers;

    gPeerThreads = peerThreads;

    /* allocate memory for peer info */
    gPeers = malloc(gPeerThreads * sizeof(PeerInfo_t));
    if (gPeers == NULL) {
        printf("Peer thread info malloc failed");
    }
    memset(gPeers, 0, gPeerThreads * sizeof(PeerInfo_t));

    for (i = 0; i < gPeerThreads; i++) {
        peer = &gPeers[i];

        peer->id = i;
        ret = pthread_create(&peer->threadId, NULL, PeerThread, peer);
        if (ret < 0) {
            perror("pthread_create failed");
            break;
        }
    }

    /* join threads */
    for (i = 0; i < gPeerThreads; i++) {
        peer = &gPeers[i];
        ret = pthread_join(peer->threadId, NULL);
        if (ret < 0) {
            perror("pthread_join failed");
            break;
        }
    }

    return ret;
}

static void StopPeers(void)
{
    gStopPeers = 1;
    KeyServer_Stop();
}

#if HAVE_SIGNAL
#include <signal.h>
static void sig_handler(int signo)
{
    if (signo == SIGINT) {
        printf("\nStopping peers\n");
        StopPeers();
    }
}
#endif

int main(int argc, char** argv)
{
    int ret = 0;
    pthread_t keySrvTid;
    int peerThreads;

    if (argc < 2) {
        printf("Usage: mcastpeer [threads]\n");
        return 0;
    }
    else {
        peerThreads = atoi(argv[1]);
    }

#if HAVE_SIGNAL
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        printf("Can't catch SIGINT\n");
    }
#endif

#if defined(DEBUG_WOLFSSL) && !defined(STACK_TRAP)
    wolfSSL_Debugging_ON();
#endif

    wolfSSL_Init();

    /* start key server */
    ret = KeyServerStart(&keySrvTid);
    if (ret != 0) {
        goto exit;
    }

    /* start peers */
    StartPeers(peerThreads);

    pthread_join(keySrvTid, NULL);

exit:

    StopPeers();

    free(gPeers);

    wolfSSL_Cleanup();

    return 0;
}
