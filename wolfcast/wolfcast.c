/* wolfcast.c */

/*
 gcc -Wall wolfcast.c -o ./wolfcast -lwolfssl

 run different clients on different hosts to see client sends,
 this is because we're disabling MULTICAST_LOOP so that we don't have to
 process messages we send ourselves

 could run ./wolfcast server on host 1 (this sends out a time msg every second)
 then run  ./wolfcast client on host 1 (will see server time msgs)
 then      ./wolfcast client on host 2 (will see server and client 1msgs, and
                                         host1 will see host2 msgs as well)

 $ ./wolfcast client <myId> <peerIdList>
 $ ./wolfcast server <myId>

 */


#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "wolfcast.h"
#include "key-services.h"
#include "key-client.h"
#include "key-server.h"


/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#ifndef WOLFCAST_LOGGING_LEVEL
    #define WOLFCAST_LOGGING_LEVEL 0
#endif

#ifndef NETX

    #include <stdlib.h>
    #include <stdio.h>
    #include <errno.h>
    #include <string.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/ioctl.h>
    #include <time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <fcntl.h>
    #include <pthread.h>

    static unsigned int WCTIME(void)
    {
        return (unsigned int)time(NULL);
    }

#if WOLFCAST_LOGGING_LEVEL >= 1
    #define WCPRINTF printf
    static void WCERR(const char *msg)
    {
        if (msg != NULL)
            fprintf(stderr, "error: %s\n", msg);
    }
#endif

    #define GROUP_ADDR "226.0.0.3"

    #ifndef LOCAL_ADDR
        #error Please define LOCAL_ADDR with IP in dot notation
    #endif


typedef struct wolfWrapper_t {
    unsigned short streamId;
    WOLFSSL_CTX* ctx;
    WOLFSSL* curSsl;
    WOLFSSL* prevSsl;
    unsigned short epoch;
    unsigned short newEpoch;
    KeyRespPacket_t keyState;
    int keySet;
    int switchKeys;
    const unsigned short* peerIdList;
    unsigned peerIdListSz;
    unsigned char myId;
    struct in_addr groupAddr;
    unsigned short groupPort;
    struct sockaddr_in tx;
    unsigned txSz;
    int txFd;
    int rxFd;
    unsigned char *rxPacket;
    unsigned long rxPacketSz;
} wolfWrapper_t;


static int gRekeyTrigger = 1;
static int gKeySet[3];
static int gSwitchKeys[3];
static KeyRespPacket_t gKeyState;
static wolfWrapper_t gWrapper[3];
static unsigned short gEpoch;


static int
WrapperDtlsTxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
    wolfWrapper_t* wrapper;
    int error = 0;
    int sendSz = 0;

    (void)ssl;

    if (ctx == NULL || buf == NULL || sz <= 0) {
        error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("receive callback invalid parameters");
#endif
    }

    if (!error) {
        wrapper = (wolfWrapper_t*)ctx;
        sendSz = (int)sendto(wrapper->txFd, buf, sz, 0,
                             (struct sockaddr*)&wrapper->tx, wrapper->txSz);
    }

    if (sendSz < 0) {
        sendSz = errno;

        if (sendSz == SOCKET_EWOULDBLOCK || sendSz == SOCKET_EAGAIN) {
            sendSz = WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        else {
            sendSz = WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    return sendSz;
}


static int
BufferDtlsRxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
    wolfWrapper_t* wrapper;
    byte *packet;
    unsigned long packetSz;
    int error = 0;

    (void)ssl;

    if (ctx == NULL || buf == NULL || sz <= 0) {
        error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("receive callback invalid parameters");
#endif
    }

    if (!error) {
        wrapper = (wolfWrapper_t*)ctx;
        packet = wrapper->rxPacket;
        packetSz = wrapper->rxPacketSz;

        if (packet == NULL || packetSz == 0) {
            error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("receive callback no rx packet");
#endif
        }
    }

    if (!error) {
        memcpy(buf, packet, packetSz);
        sz = (int)packetSz;
        wrapper->rxPacket = NULL;
    }
    else {
        sz = WOLFSSL_CBIO_ERR_GENERAL;
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("rx error");
#endif
    }

    return sz;
}


int wolfWrapper_Init(wolfWrapper_t* wrapper, int isClient,
                     unsigned short streamId, unsigned short myId,
                     unsigned short groupPort, struct in_addr* groupAddr,
                     const unsigned short *peerIdList, unsigned peerIdListSz,
                     void* heap, unsigned heapSz)
{
    int error = 1;
    int on = 1, off = 0;
    int ret;

#if WOLFCAST_LOGGING_LEVEL >= 1
    WCPRINTF("Entering wolfWrapper_Init\n");
#endif

    if (wrapper == NULL ||
        (isClient && (peerIdList == NULL || peerIdListSz == 0)) ||
        groupAddr == NULL || groupPort == 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("wolfWrapper_Init bad arguments");
#endif
        goto exit;
    }

    memset(wrapper, 0, sizeof(wolfWrapper_t));

    wrapper->streamId = streamId;
    wrapper->myId = myId;
    wrapper->groupAddr = *groupAddr;
    wrapper->groupPort = groupPort;
    wrapper->peerIdList = peerIdList;
    wrapper->peerIdListSz = peerIdListSz;

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("wolfWrapper_Init couldn't initialize wolfSSL\n");
#endif
        goto exit;
    }

    wrapper->ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    if (wrapper->ctx == NULL) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("unable to create ctx\n");
#endif
        goto exit;
    }

    wolfSSL_SetIOSend(wrapper->ctx, WrapperDtlsTxCallback);
    wolfSSL_SetIORecv(wrapper->ctx, BufferDtlsRxCallback);
    ret = wolfSSL_CTX_mcast_set_member_id(wrapper->ctx, myId);
    if (ret != SSL_SUCCESS) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("set mcast member id error\n");
#endif
        goto exit;
    }

    wrapper->tx.sin_family = AF_INET;
    wrapper->tx.sin_addr = *groupAddr;
    wrapper->tx.sin_port = htons(groupPort);
    wrapper->txSz = sizeof(wrapper->tx);

    wrapper->txFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (wrapper->txFd < 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("unable to create tx socket");
#endif
        goto exit;
    }

    if (setsockopt(wrapper->txFd, SOL_SOCKET, SO_REUSEADDR,
                   &on, sizeof(on)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("couldn't set tx reuse addr");
#endif
        goto exit;
    }

#ifndef SO_REUSEPORT
    if (setsockopt(wrapper->txFd, SOL_SOCKET, SO_REUSEPORT,
                   &on, sizeof(on)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("couldn't set tx reuse port");
#endif
        goto exit;
    }
#endif

    /* Non-generic solution to a local problem. */
    {
        struct in_addr addr;

        memset(&addr, 0, sizeof(addr));
        addr.s_addr = inet_addr(LOCAL_ADDR);

        if (setsockopt(wrapper->txFd, IPPROTO_IP, IP_MULTICAST_IF,
                       (const void*)&addr, sizeof(addr)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("setsockopt mc set multicast interface failed");
#endif
            goto exit;
        }
    }

    if (!isClient) {
        error = 0;
        goto exit;
    }

    /* don't send to self */
    if (setsockopt(wrapper->txFd, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &off, sizeof(off)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("couldn't disable multicast loopback");
#endif
        goto exit;
    }

    wrapper->rxFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (wrapper->rxFd < 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("unable to create rx socket");
#endif
        goto exit;
    }

    if (setsockopt(wrapper->rxFd, SOL_SOCKET, SO_REUSEADDR,
                   &on, (unsigned int)sizeof(on)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("couldn't set rx reuse addr");
#endif
        goto exit;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(wrapper->rxFd, SOL_SOCKET, SO_REUSEPORT,
                   &on, (unsigned int)sizeof(on)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("couldn't set rx reuse port");
#endif
        goto exit;
    }
#endif

    {
        struct sockaddr_in rxAddr;

        memset(&rxAddr, 0, sizeof(rxAddr));
        rxAddr.sin_family = AF_INET;
        rxAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        rxAddr.sin_port = htons(groupPort);

        if (bind(wrapper->rxFd,
                 (struct sockaddr*)&rxAddr, sizeof(rxAddr)) != 0) {

#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("rx bind failed");
#endif
            goto exit;
        }
    }

    {
        struct ip_mreq imreq;
        memset(&imreq, 0, sizeof(imreq));

        imreq.imr_multiaddr = *groupAddr;
#ifndef LOCAL_ADDR
        /* Non-generic solution to a local problem. */
        imreq.imr_interface.s_addr = htonl(INADDR_ANY);
#else
        imreq.imr_interface.s_addr = inet_addr(LOCAL_ADDR);
#endif

        if (setsockopt(wrapper->rxFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (const void*)&imreq, sizeof(imreq)) != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("setsockopt mc add membership failed");
#endif
            goto exit;
        }
    }

    if (fcntl(wrapper->rxFd, F_SETFL, O_NONBLOCK) == -1) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("set nonblock failed");
#endif
        goto exit;
    }
    error = 0;

exit:
    return error;
}


typedef struct EpochPeek {
    unsigned char pad[3];
    unsigned char epoch[2];
} EpochPeek;


static unsigned short GetEpoch(const byte *buf)
{
    unsigned short epoch = 0;

    if (buf != NULL) {
        EpochPeek *peek = (EpochPeek*)buf;
        epoch = (peek->epoch[0] << 8) | peek->epoch[1];
    }

    return epoch;
}

static int wolfWrapper_Read(wolfWrapper_t* wrapper, unsigned short* peerId,
                            void* buf, int sz)
{
    WOLFSSL *ssl = NULL;
    unsigned short epoch;
    int recvSz = 0;
    byte packet[1500];
    ssize_t n;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering wolfWrapper_Read\n");
#endif

    if (wrapper == NULL || buf == NULL || sz == 0)
        goto exit;

    n = recvfrom(wrapper->rxFd, packet, sizeof(packet), 0, NULL, 0);
    if (n <= 0)
        goto exit;

    wrapper->rxPacket = packet;
    wrapper->rxPacketSz = (unsigned long)n;
    epoch = GetEpoch(packet);
    if (epoch == wrapper->epoch)
        ssl = wrapper->curSsl;
    else if (epoch < wrapper->epoch)
        ssl = wrapper->prevSsl;
    else if (epoch > wrapper->epoch) {
        /* We may have missed a new key update or a switch keys. */
        gRekeyTrigger = 1;
    }

    if (ssl == NULL) {
#if WOLFCAST_LOGGING_LEVEL >= 3
        WCPRINTF("Ignoring message unknown Epoch.\n");
#endif
        goto exit;
    }

    recvSz = wolfSSL_mcast_read(ssl, peerId, buf, sz);
    if (recvSz < 0) {
        recvSz = wolfSSL_get_error(ssl, recvSz);
        if (recvSz == VERIFY_MAC_ERROR || recvSz == DECRYPT_ERROR) {
#if WOLFCAST_LOGGING_LEVEL >= 3
            WCPRINTF("Allowable DTLS error. Ignoring a message.\n");
#endif
        }
        else if (recvSz != SSL_ERROR_WANT_READ) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCPRINTF("wolfSSL error: %s\n",
                      wolfSSL_ERR_reason_error_string(recvSz));
#endif
        }
    }

exit:
    wrapper->rxPacket = NULL;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Leaving wolfWrapper_Read, ret = %d\n", recvSz);
#endif
    return recvSz;
}


static int wolfWrapper_Write(wolfWrapper_t* wrapper, const void* buf, int sz)
{
    int sentSz = 0;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering wolfWrapper_Write\n");
#endif
    
/* If there isn't a curSsl, return want write? */
    if (wrapper == NULL || wrapper->curSsl == NULL || buf == NULL || sz == 0)
        goto exit;

    sentSz = wolfSSL_write(wrapper->curSsl, buf, sz);
    if (sentSz < 0) {
        sentSz = wolfSSL_get_error(wrapper->curSsl, sentSz);
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCPRINTF("wolfSSL error: %s\n",
                  wolfSSL_ERR_reason_error_string(sentSz));
#endif
    }

exit:
#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Leaving wolfWrapper_Write, ret = %d\n", sentSz);
#endif
    return sentSz;
}


static int wolfWrapper_NewSession(wolfWrapper_t* wrapper, WOLFSSL** ssl)
{
    int ret = SSL_SUCCESS;
    int i;
    WOLFSSL* newSsl = NULL;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering wolfWrapper_NewSession\n");
#endif

    if (wrapper == NULL || ssl == NULL) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCPRINTF("wolfWrapper_NewSession invalid parameters\n");
#endif
        goto exit;
    }

    newSsl = wolfSSL_new(wrapper->ctx);
    if (newSsl == NULL) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCPRINTF("ssl new error\n");
#endif
        goto exit;
    }

    wolfSSL_SetIOWriteCtx(newSsl, wrapper);
    wolfSSL_SetIOReadCtx(newSsl, wrapper);
    wolfSSL_set_using_nonblock(newSsl, 1);

    for (i = 0; i < wrapper->peerIdListSz; i++) {
        ret = wolfSSL_mcast_peer_add(newSsl, wrapper->peerIdList[i], 0);
        if (ret != SSL_SUCCESS) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCPRINTF("mcast add peer error\n");
#endif
            goto exit;
        }
    }

    *ssl = newSsl;
    newSsl = NULL;

exit:
    if (newSsl)
        wolfSSL_free(newSsl);

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Leaving wolfWrapper_NewSession, ret = %d\n",
             (ret != SSL_SUCCESS));
#endif
    return (ret != SSL_SUCCESS);
}


int wolfWrapper_Update(wolfWrapper_t* wrapper)
{
    int status;
    int error = 0;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering wolfWrapper_Update\n");
#endif
    if (wrapper == NULL) {
        error = 1;
        goto exit;
    }

    if (!wrapper->keySet && !wrapper->switchKeys) {
        wrapper->keySet = gKeySet[wrapper->streamId];
        gKeySet[wrapper->streamId] = 0;
        wrapper->switchKeys = gSwitchKeys[wrapper->streamId];
        gSwitchKeys[wrapper->streamId] = 0;

        if (wrapper->keySet) {
            memcpy(&wrapper->keyState, &gKeyState, sizeof(gKeyState));
        }
    }

    if (wrapper->keySet) {
        wrapper->keySet = 0;
        wrapper->newEpoch = (wrapper->keyState.epoch[0] << 8) |
                            wrapper->keyState.epoch[1];
    }

    if (wrapper->switchKeys) {
#if WOLFCAST_LOGGING_LEVEL >= 3
        WCPRINTF("switchKeys = %u, newEpoch = %u, epoch = %u\n",
                 wrapper->switchKeys, wrapper->newEpoch, wrapper->epoch);
#endif
        if (wrapper->switchKeys == wrapper->newEpoch &&
            wrapper->newEpoch != wrapper->epoch) {

            WOLFSSL *newSsl = NULL;

            wrapper->switchKeys = 0;
            status = wolfWrapper_NewSession(wrapper, &newSsl);
            if (status != 0) {
                error = 1;
                goto exit;
            }

            status = wolfSSL_set_secret(newSsl, wrapper->newEpoch,
                            wrapper->keyState.pms,
                            sizeof(wrapper->keyState.pms),
                            wrapper->keyState.clientRandom[wrapper->streamId],
                            wrapper->keyState.serverRandom[wrapper->streamId],
                            wrapper->keyState.suite);
            if (status != SSL_SUCCESS) {
                error = 1;
                wolfSSL_free(newSsl);
#if WOLFCAST_LOGGING_LEVEL >= 1
                WCERR("Couldn't set the session secret\n");
#endif
                goto exit;
            }
            memset(&wrapper->keyState, 0, sizeof(wrapper->keyState));

            if (wrapper->prevSsl != NULL) {
#if WOLFCAST_LOGGING_LEVEL >= 3
                WCPRINTF("Releasing old session.\n");
#endif
                wolfSSL_free(wrapper->prevSsl);
            }
            wrapper->prevSsl = wrapper->curSsl;
            wrapper->curSsl = newSsl;
            wrapper->epoch = wrapper->newEpoch;
            newSsl = NULL;
        }
        else if (wrapper->switchKeys == wrapper->epoch) {
            /* Happens when a client rejoins, the master rekeys,
             * and sends out the rekey messages for the peers. */
#if WOLFCAST_LOGGING_LEVEL >= 3
            WCPRINTF("Spurious key switch, ignoring.\n");
#endif
        }
        else {
#if WOLFCAST_LOGGING_LEVEL >= 2
            WCPRINTF("Missed a key change.\n");
#endif
            gRekeyTrigger = 1;
        }

        wrapper->switchKeys = 0;
    }

exit:
#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Leaving wolfWrapper_Update, ret = %d\n", error);
#endif
    return error;
}


#else /* NETX */

    #include "wolflocal.h"

    static unsigned int WCTIME(void)
    {
        return (unsigned int)(bsp_fast_timer_uptime() / 1000000);
    }

#if WOLFCAST_LOGGING_LEVEL >= 1
    #define WCPRINTF bsp_debug_printf
    static void WCERR(const char *msg)
    {
        if (msg != NULL)
            bsp_debug_printf("error: %s\n", msg);
    }
#endif

//    #define GROUP_ADDR 0xE2000003

extern UINT gGetNewKey;
extern UINT gSwitchKeys[3];

#endif


#define MSG_SIZE 80


#ifndef NO_WOLFCAST_CLIENT


#ifndef NETX

#endif /* !NETX */


static inline unsigned int
WolfcastClientUpdateTimeout(unsigned int curTime)
{
    return curTime + 3;
}


int
WolfcastClientInit(unsigned int *txtime, unsigned int *count)
{
    int error = 0;
    if (txtime != NULL && count != NULL) {
        *txtime = WCTIME();
        *count = 0;
    }
    else
        error = 1;
    return error;
}


int
WolfcastClient(wolfWrapper_t *wrapper,
               unsigned int *txtime, unsigned int *count)
{
    int error = 0;
    char msg[MSG_SIZE];

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering WolfcastClient\n");
#endif

    if (wrapper == NULL || txtime == NULL || count == NULL) {
        /* prevSsl is allowed to be NULL, and is checked later. */
        error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("WolfcastClient bad parameters");
#endif
    }

    if (!error) {
        unsigned short peerId;
        int n = wolfWrapper_Read(wrapper, &peerId, msg, MSG_SIZE);
        if (n > 0) {
#if WOLFCAST_LOGGING_LEVEL >= 3
            WCPRINTF("msg from peer %u: %s\n", peerId, msg);
#endif
        }
    }

    if (!error) {
        unsigned int rxtime;

        rxtime = WCTIME();
        if (rxtime >= *txtime) {
            int msg_len;
            int n;

            sprintf(msg, "%u sending message %d", wrapper->myId, (*count)++);
            msg_len = (int)strlen(msg) + 1;
            n = wolfWrapper_Write(wrapper, msg, msg_len);
            if (n < 0) {
                error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
                n = wolfSSL_get_error(wrapper->curSsl, n);
                WCERR(wolfSSL_ERR_reason_error_string(n));
#endif
            }
            else
                *txtime = WolfcastClientUpdateTimeout(rxtime);
        }
    }

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Leaving WolfcastClient, ret = %d\n", error);
#endif
    return error;
}

#endif


#ifndef NO_WOLFCAST_SERVER

int
WolfcastServer(wolfWrapper_t *wrapper)
{
    int error = 0;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering WolfcastServer\n");
#endif

    if (wrapper == NULL) {
        error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("WolfcastServer bad parameters");
#endif
    }

    if (!error) {
        unsigned int msg_len;
        char msg[80];
        int n;

        sprintf(msg, "peer %u time is %us", wrapper->myId, WCTIME());
        msg_len = (unsigned int)strlen(msg) + 1;
        n = wolfWrapper_Write(wrapper, msg, msg_len);
        if (n < 0) {
            error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
            n = wolfSSL_get_error(wrapper->curSsl, n);
            WCERR(wolfSSL_ERR_reason_error_string(n));
#endif
        }
    }

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Leaving WolfcastServer, ret = %d\n", error);
#endif
    return error;
}

#endif


#ifndef NO_MAIN_DRIVER

#define PEER_ID_LIST_SZ 99
#define GROUP_PORT 12345


    static void KeyBcastReqPktCallback(CmdPacket_t* pkt)
    {
        if (pkt) {
            if (pkt->header.type == CMD_PKT_TYPE_KEY_CHG) {
#if WOLFCAST_LOGGING_LEVEL >= 3
                unsigned char* addr = pkt->msg.keyChgResp.ipaddr;
                WCPRINTF("Key Change Server: %d.%d.%d.%d\n",
                         addr[0], addr[1], addr[2], addr[3]);
#endif
                /* trigger key change */
                gRekeyTrigger = 1;
            }
            else if (pkt->header.type == CMD_PKT_TYPE_KEY_USE) {
                /* use the new key */
                unsigned short epoch = (pkt->msg.epochResp.epoch[0] << 8) |
                                        pkt->msg.epochResp.epoch[1];
                gSwitchKeys[0] = epoch;
                gSwitchKeys[1] = epoch;
                gSwitchKeys[2] = epoch;
                gEpoch = epoch;
#if WOLFCAST_LOGGING_LEVEL >= 3
                WCPRINTF("Use the new key for epoch %u.\n", epoch);
#endif
            }
            else if (pkt->header.type == CMD_PKT_TYPE_DISCOVER) {
            }
        }
    }

    static void* KeyBcastThread(void* arg)
    {
        int ret;
        struct in_addr srvAddr;
        unsigned char addr[4] = {KEY_BCAST_ADDR};

        (void)arg;

        XMEMCPY(&srvAddr.s_addr, addr, sizeof(srvAddr.s_addr));

        ret = KeyBcast_RunUdp(&srvAddr, KeyBcastReqPktCallback, NULL);

        if (ret) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCPRINTF("error: KeyBcast_RunUdp returned %d\n", ret);
#endif
        }

        return NULL;
    }


static void* WolfCastClientThread(void* arg)
{
#ifndef NO_WOLFCAST_CLIENT
    wolfWrapper_t* wrapper = (wolfWrapper_t*)arg;
    unsigned int txtime, count;
    int error = 0;

    if (wrapper == NULL)
        error = 1;

    while (!gKeySet[wrapper->streamId]) {
#if WOLFCAST_LOGGING_LEVEL >= 2
        WCPRINTF("Waiting for the first key.\n");
#endif
        sleep(1);
    }

    if (!error)
        error = WolfcastClientInit(&txtime, &count);

    while (!error) {
        error = wolfWrapper_Update(wrapper);
/*
        if (!error) {
            fd_set readfds;
            struct timeval timeout = {0, 500000};

            FD_ZERO(&readfds);
            FD_SET(wrapper->rxFd, &readfds);
            error = select(wrapper->rxFd+1, &readfds,
                           NULL, NULL, &timeout) < 0;
        }
*/
        if (!error)
            error = WolfcastClient(wrapper, &txtime, &count);
        if (!error)
            sleep(1);
    }
#else /* NO_WOLFCAST_CLIENT */
    (void)arg;
    error = 1;
#endif /* NO_WOLFCAST_CLIENT */

    return NULL;
}


static void* WolfCastServerThread(void* arg)
{
#ifndef NO_WOLFCAST_SERVER
    wolfWrapper_t* wrapper = (wolfWrapper_t*)arg;
    int error = 0;

    if (wrapper == NULL)
        error = 1;

    while (!gKeySet[wrapper->streamId]) {
#if WOLFCAST_LOGGING_LEVEL >= 2
        WCPRINTF("Waiting for the first key.\n");
#endif
        sleep(1);
    }
    gSwitchKeys[wrapper->streamId] = (gKeyState.epoch[0] << 8) |
                                     gKeyState.epoch[1];

    while (!error) {
        error = wolfWrapper_Update(wrapper);

        if (!error)
            error = WolfcastServer(wrapper);

        if (!error)
            sleep(1);
    }
#else /* NO_WOLFCAST_SERVER */
    (void)arg;
    error = 1;
#endif /* NO_WOLFCAST_SERVER */

    return NULL;
}


static void FetchNewKey(void)
{
    unsigned char addr[4] = {KEY_BCAST_ADDR};
    struct in_addr keySrvAddr;
    KeyRespPacket_t keyState;
    int ret;
    unsigned short newEpoch;

#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Entering FetchNewKey\n");
#endif
    memset(&keySrvAddr, 0, sizeof(keySrvAddr));
    memcpy(&keySrvAddr.s_addr, addr, sizeof(addr));
    ret = KeyClient_FindMaster(&keySrvAddr, NULL);

    if (ret != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
        WCERR("unable to find master");
#endif
        /* The recv times out here, which is normal, is
         * treated as an error. */
        return;
    }

    memcpy(addr, &keySrvAddr.s_addr, sizeof(addr));
#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Found Server: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
#endif

    ret = KeyClient_GetKey(&keySrvAddr, &keyState, NULL);
    if (ret != 0) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("Key retrieval failed");
#endif
            return;
    }
    gRekeyTrigger = 0;

    newEpoch = (keyState.epoch[0] << 8) | keyState.epoch[1];
    if (newEpoch > gEpoch) {
#if WOLFCAST_LOGGING_LEVEL >= 3
        WCPRINTF("key set newEpoch = %u\n", newEpoch);
#endif
        memcpy(&gKeyState, &keyState, sizeof(keyState));
        gKeySet[0] = 1;
        gKeySet[1] = 1;
        gKeySet[2] = 1;
    }
    else {
#if WOLFCAST_LOGGING_LEVEL >= 3
        WCPRINTF("Ignoring already used epoch.\n");
#endif
    }

    return;
}


static void ShowUsage(void)
{
#if WOLFCAST_LOGGING_LEVEL >= 3
    WCPRINTF("Usage: wolfcast client <id> <peer list>\n"
             "       wolfcast server <id>\n");
#endif
}


int
main(
    int argc,
    char** argv)
{
    int error = 0;
    int isClient = 0;
    unsigned short myId = 0;
    unsigned short peerIdList[PEER_ID_LIST_SZ];
    unsigned int peerIdListSz = 0;
    struct in_addr keySrvAddr = { .s_addr = inet_addr("192.168.20.1") };

    if (argc == 3 || argc == 4) {
        long n;

        if (strcmp("client", argv[1]) == 0)
            isClient = 1;
        else if (strcmp("server", argv[1]) != 0) {
            ShowUsage();
            error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("type must be either client or server");
#endif
        }

        if (!error) {
            if ((isClient && argc != 4) || (!isClient && argc != 3)) {
                error = 1;
                ShowUsage();
            }
        }

        if (!error) {
            n = strtol(argv[2], NULL, 10);
            if (n >= 0 && n < 256)
                myId = n;
            else {
                error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
                WCERR("id must be between 0 and 255, inclusive");
#endif
            }
        }

        if (!error && isClient) {
            char *str = argv[3];
            char *endptr = argv[3];

            do {
                if (peerIdListSz == PEER_ID_LIST_SZ) {
                    error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
                    WCERR("too many peer ids");
#endif
                    break;
                }

                n = strtol(str, &endptr, 10);
                if (n >= 0 && n < 256) {
                    peerIdList[peerIdListSz] = n;
                    peerIdListSz++;

                    if (*endptr == ':')
                        str = endptr + 1;
                }
                else {
                    error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
                    WCERR("peer ids must be between 0 and 255, inclusive");
#endif
                    break;
                }
            }
            while (*endptr != '\0');
        }
    }
    else {
        error = 1;
        ShowUsage();
    }

    KeyServices_Init(myId, 22222, 11111);

    if (!error) {
        signal(SIGPIPE, SIG_IGN);

        error = KeyServer_Init(NULL, &keySrvAddr);
        if (error) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("couldn't init key service");
#endif
        }
    }

    /* Start up the threads */
    if (!error) {
        int i;
        pthread_t tid;

        /* spin up the thread for UDP broadcast */
        error = pthread_create(&tid, NULL, KeyBcastThread, NULL) != 0;

        if (error) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("couldn't create KeyBcastThread");
#endif
        }

        if (!error)
            error = pthread_detach(tid) != 0;

        if (error) {
#if WOLFCAST_LOGGING_LEVEL >= 1
            WCERR("couldn't detach KeyBcastThread");
#endif
        }

        /* spin up the thread three stream threads */
        for (i = 0; i < 1; i++) {
            struct in_addr groupAddr;
            groupAddr.s_addr = inet_addr(GROUP_ADDR);
            error = wolfWrapper_Init(&gWrapper[i], isClient, i, myId,
                                     GROUP_PORT, &groupAddr,
                                     peerIdList, peerIdListSz, NULL, 0);
            if (error) {
#if WOLFCAST_LOGGING_LEVEL >= 1
                WCPRINTF("couldn't initialize wolfWrapper #%u\n", i);
#endif
                break;
            }
            if (isClient)
                error = pthread_create(&tid, NULL,
                                       WolfCastClientThread, &gWrapper[i]) != 0;
            else
                error = pthread_create(&tid, NULL,
                                       WolfCastServerThread, &gWrapper[i]) != 0;
            if (error) {
#if WOLFCAST_LOGGING_LEVEL >= 1
                WCPRINTF("couldn't create wolfCast client thread #%u\n", i);
#endif
                break;
            }
            error = pthread_detach(tid) != 0;
            if (error) {
#if WOLFCAST_LOGGING_LEVEL >= 1
                WCPRINTF("couldn't detach wolfCast client thread #%u\n", i);
#endif
                break;
            }
        }
    }

    if (!error) {
        for(;;) {
            if (gRekeyTrigger)
                FetchNewKey();
            sleep(1);
        }
    }

    return error;
}

#endif /* NO_MAIN_DRIVER */
