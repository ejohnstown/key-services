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
#include "key-beacon.h"


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

    static unsigned int WCTIME(void)
    {
        return (unsigned int)time(NULL);
    }

    #define WCPRINTF printf

    static void WCERR(const char *msg)
    {
        if (msg != NULL)
            fprintf(stderr, "error: %s\n", msg);
    }

    #define GROUP_ADDR "226.0.0.3"
    #define GROUP_PORT 12345

    #ifndef LOCAL_ADDR
        #define LOCAL_ADDR "192.168.0.111"
    #endif


static int
BufferDtlsRxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
    SocketInfo_t *si;
    byte *packet;
    unsigned long packetSz;
    int error = 0;

    (void)ssl;

    if (ctx == NULL || buf == NULL || sz <= 0) {
        error = 1;
        WCERR("receive callback invalid parameters");
    }

    if (!error) {
        si = (SocketInfo_t*)ctx;
        packet = si->rxPacket;
        packetSz = si->rxPacketSz;

        if (packet == NULL || packetSz == 0) {
            error = 1;
            WCERR("receive callback no rx packet");
        }
    }

    if (!error) {
        memcpy(buf, packet, packetSz);
        sz = (int)packetSz;
        si->rxPacket = NULL;
    }
    else {
        sz = WOLFSSL_CBIO_ERR_GENERAL;
        WCERR("rx error");
    }

    return sz;
}


static int
CreateSockets(SocketInfo_t* si, int isClient)
{
    int error = 0, on = 1, off = 0;

    if (si == NULL) {
        error = 1;
        WCERR("no socket info");
    }

    if (!error) {
        si->tx.sin_family = AF_INET;
        si->tx.sin_addr.s_addr = inet_addr(GROUP_ADDR);
        si->tx.sin_port = htons(GROUP_PORT);
        si->txSz = sizeof(si->tx);

        si->txFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (si->txFd < 0) {
            error = 1;
            WCERR("unable to create tx socket");
        }
    }

    if (!error) {
        if (setsockopt(si->txFd, SOL_SOCKET, SO_REUSEADDR,
                       &on, sizeof(on)) != 0) {
            error = 1;
            WCERR("couldn't set tx reuse addr");
        }
    }
#ifdef SO_REUSEPORT
    if (!error) {
        if (setsockopt(si->txFd, SOL_SOCKET, SO_REUSEPORT,
                       &on, sizeof(on)) != 0) {
            error = 1;
            WCERR("couldn't set tx reuse port");
        }
    }
#endif

    /* Non-generic solution to a local problem. */
    if (!error) {
        struct in_addr addr;

        memset(&addr, 0, sizeof(addr));
        addr.s_addr = inet_addr(LOCAL_ADDR);

        if (setsockopt(si->txFd, IPPROTO_IP, IP_MULTICAST_IF,
                    (const void*)&addr, sizeof(addr)) != 0) {
            error = 1;
            WCERR("setsockopt mc set multicast interface failed");
        }
    }

    if (!isClient)
        return error;

    if (!error) {
        /* don't send to self */
        if (setsockopt(si->txFd, IPPROTO_IP, IP_MULTICAST_LOOP,
                       &off, sizeof(off)) != 0) {
            error = 1;
            WCERR("couldn't disable multicast loopback");
        }
    }

    if (!error) {
        si->rxFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (si->rxFd < 0) {
            error = 1;
            WCERR("unable to create rx socket");
        }
    }

    if (!error) {
        if (setsockopt(si->rxFd, SOL_SOCKET, SO_REUSEADDR,
                       &on, (unsigned int)sizeof(on)) != 0) {
            error = 1;
            WCERR("couldn't set rx reuse addr");
        }
    }
#ifdef SO_REUSEPORT
    if (!error) {
        if (setsockopt(si->rxFd, SOL_SOCKET, SO_REUSEPORT,
                       &on, (unsigned int)sizeof(on)) != 0) {
            error = 1;
            WCERR("couldn't set rx reuse port");
        }
    }
#endif
    if (!error) {
        struct sockaddr_in rxAddr;

        memset(&rxAddr, 0, sizeof(rxAddr));
        rxAddr.sin_family = AF_INET;
        rxAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        rxAddr.sin_port = htons(GROUP_PORT);

        if (bind(si->rxFd,
                 (struct sockaddr*)&rxAddr, sizeof(rxAddr)) != 0) {

            error = 1;
            WCERR("rx bind failed");
        }
    }

    if (!error) {
        struct ip_mreq imreq;
        memset(&imreq, 0, sizeof(imreq));

        imreq.imr_multiaddr.s_addr = inet_addr(GROUP_ADDR);
#ifndef LOCAL_ADDR
        /* Non-generic solution to a local problem. */
        imreq.imr_interface.s_addr = htonl(INADDR_ANY);
#else
        imreq.imr_interface.s_addr = inet_addr(LOCAL_ADDR);
#endif

        if (setsockopt(si->rxFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (const void*)&imreq, sizeof(imreq)) != 0) {
            error = 1;
            WCERR("setsockopt mc add membership failed");
        }
    }

    if (!error) {
        if (fcntl(si->rxFd, F_SETFL, O_NONBLOCK) == -1) {
            error = 1;
            WCERR("set nonblock failed");
        }
    }

    return error;
}

#else /* NETX */

    static unsigned int WCTIME(void)
    {
        return (unsigned int)bsp_fast_timer_uptime() / 1000000;
    }

    #define WCPRINTF bsp_debug_printf

    static void WCERR(const char *msg)
    {
        if (msg != NULL)
            bsp_debug_printf("error: %s\n", msg);
    }

    #define GROUP_ADDR 0xE2000003
    #define GROUP_PORT 12345

    static struct in_addr keySrvAddr = { IP_ADDRESS(192,168,2,1) };
    static int hasKey = 0;


static int
NetxDtlsTxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
    SocketInfo_t* si;
    NX_PACKET *pkt = NULL;
    unsigned int ret;
    int error = 0;

    (void)ssl;
    if (ctx == NULL || buf == NULL) {
        error = 1;
        WCERR("transmit callback invalid parameters");
    }

    if (!error) {
        si = (SocketInfo_t*)ctx;

        ret = nx_packet_allocate(si->pool, &pkt, NX_UDP_PACKET, NX_WAIT_FOREVER);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("couldn't allocate packet wrapper");
        }
    }

    if (!error) {
        ret = nx_packet_data_append(pkt, buf, sz, si->pool, NX_WAIT_FOREVER);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("couldn't append data to packet");
        }
    }

    if (!error) {
        ret = nx_udp_socket_send(&si->txSocket, pkt,
                                 si->ipAddr, si->port);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("tx error");
        }
    }

    if (error) {
        sz = WOLFSSL_CBIO_ERR_GENERAL;

        /* In case of error, release packet. */
        ret = nx_packet_release(pkt);
        if (ret != NX_SUCCESS) {
            WCERR("couldn't release packet");
        }
    }

    return sz;
}


static int
NetxDtlsRxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
    SocketInfo_t *si;
    NX_PACKET *pkt = NULL;
    unsigned long rxSz = 0;
    unsigned int ret;
    int error = 0;

    (void)ssl;
    if (ctx == NULL || buf == NULL || sz <= 0) {
        error = 1;
        WCERR("receive callback invalid parameters");
    }

    if (!error) {
        si = (SocketInfo_t*)ctx;
        pkt = si->rxPacket;

        ret = nx_packet_length_get(pkt, &rxSz);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("couldn't get packet length");
        }
    }

    if (!error) {
        if (rxSz > (unsigned long)sz) {
            error = 1;
            WCERR("receive packet too large for buffer");
        }
    }

    if (!error) {
        ret = nx_packet_data_retrieve(pkt, buf, &rxSz);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("couldn't retrieve packet");
        }
    }

    if (pkt != NULL) {
        ret = nx_packet_release(pkt);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("couldn't release packet");
        }
    }

    if (!error) {
        sz = (int)rxSz;
        si->rxPacket = NULL;
    }
    else {
        if (ret == NX_NO_PACKET)
            sz = WOLFSSL_CBIO_ERR_WANT_READ;
        else {
            sz = WOLFSSL_CBIO_ERR_GENERAL;
            WCERR("rx error");
        }
    }

    return sz;
}


static int
CreateSockets(SocketInfo_t* si, int isClient)
{
    int error = 0;
    unsigned int ret;

    if (si == NULL) {
        error = 1;
        WCERR("no socket info");
    }

    if (!error) {
        si->ipAddr = GROUP_ADDR;
        si->port = GROUP_PORT;
#ifdef PGB000
        si->ip = &bsp_ip_system_bus;
        si->pool = &bsp_pool_system_bus;
#else /* PGB002 */
        si->ip = &bsp_ip_local_bus;
        si->pool = &bsp_pool_local_bus;
#endif
        ret = nx_udp_enable(si->ip);
        if (ret == NX_ALREADY_ENABLED) {
            WCPRINTF("UDP already enabled\n");
        }
        else if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("cannot enable UDP");
            WCPRINTF("cannot enable UDP ret = %u\n", ret);
        }
    }

    if (!error) {
        ret = nx_igmp_enable(si->ip);

        if (ret == NX_ALREADY_ENABLED) {
            WCPRINTF("IGMP already enabled\n");
        }
        else if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("cannot enable IGMP");
        }
    }

    if (!error) {
        ret = nx_udp_socket_create(si->ip, &si->txSocket,
                                   "Multicast TX Socket",
                                   NX_IP_NORMAL, NX_DONT_FRAGMENT,
                                   NX_IP_TIME_TO_LIVE, 30);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("unable to create tx socket");
        }
    }

    if (!error) {
        ret = nx_udp_socket_bind(&si->txSocket, NX_ANY_PORT, NX_NO_WAIT);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("tx bind failed");
        }
    }

    if (!isClient)
        return error;

    if (!error) {
        ret = nx_igmp_loopback_disable(si->ip);

        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("couldn't disable multicast loopback");
        }
    }

    if (!error) {
        ret = nx_udp_socket_create(si->ip, &si->rxSocket,
                                   "Multicast RX Socket",
                                   NX_IP_NORMAL, NX_DONT_FRAGMENT,
                                   NX_IP_TIME_TO_LIVE, 30);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("unable to create rx socket");
        }
    }

    if (!error) {
        ret = nx_udp_socket_bind(&si->rxSocket, GROUP_PORT, NX_NO_WAIT);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("rx bind failed");
        }
    }

    if (!error) {
        ret = nx_igmp_multicast_join(si->ip, GROUP_ADDR);
        if (ret != NX_SUCCESS) {
            error = 1;
            WCERR("setsockopt mc add membership failed");
        }
    }

    return error;
}

#endif


const char seqHwCbCtx[] = "Callback context string.";

static int seq_cb(word16 peerId, word32 maxSeq, word32 curSeq, void* ctx)
{
    const char* ctxStr = (const char*)ctx;

    WCPRINTF("Highwater Callback (%u:%u/%u): %s\n", peerId, curSeq, maxSeq,
          ctxStr != NULL ? ctxStr : "Forgot to set the callback context.");

    return 0;
}


#define MSG_SIZE 80


#ifdef WOLFSSL_STATIC_MEMORY
    #if defined(NETX) && defined(PGB002)
        #define MEMORY_SECTION LINK_SECTION(data_sdram)
    #else
        #define MEMORY_SECTION
    #endif
    MEMORY_SECTION unsigned char memory[80000];
    MEMORY_SECTION unsigned char memoryIO[34500];
#endif


/* WolfcastSessionNew
 * In separating out setup from run behavior, the contents of this
 * function used to be in WolfcastInit(). A new session will be created
 * every time there is a new key. The old session will be kept around
 * for a short time to allow a device to keep receiving messages from
 * devices that haven't rekeyed yet.
 *
 * This creates a new wolfSSL object and applies the same settings to
 * it. If any step fails after a successful instantiation of the object,
 * it will be freed. */
int
WolfcastSessionNew(WOLFSSL **ssl, WOLFSSL_CTX *ctx,
                   SocketInfo_t *si, int isClient,
                   const unsigned short *peerIdList,
                   unsigned int peerIdListSz)
{
    int error = 0;
    int ret;

    if (ctx == NULL || ssl == NULL || si == NULL ||
        (isClient && (peerIdList == NULL || peerIdListSz == 0))) {

        error = 1;
        WCERR("WolfcastSessionNew invalid parameters");
    }

    if (!error) {
        *ssl = wolfSSL_new(ctx);
        if (*ssl == NULL) {
            error = 1;
            WCERR("ssl new error");
        }
    }

#ifndef NETX
    if (!error && isClient) {
        wolfSSL_SetIOReadCtx(*ssl, si);
    }

    if (!error) {
        ret = wolfSSL_set_write_fd(*ssl, si->txFd);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl write fd error");
        }
    }

    if (!error) {
        ret = wolfSSL_dtls_set_peer(*ssl, &si->tx, si->txSz);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl sender error");
        }
    }
#else
    if (!error) {
        wolfSSL_SetIOWriteCtx(*ssl, si);
        wolfSSL_SetIOReadCtx(*ssl, si);
    }
#endif

    if (isClient) {
        if (!error) {
            wolfSSL_set_using_nonblock(*ssl, 1);
            ret = wolfSSL_mcast_set_highwater_ctx(*ssl, (void*)seqHwCbCtx);
            if (ret != SSL_SUCCESS) {
                error = 1;
                WCERR("set highwater ctx error");
            }
        }

        if (!error) {
            unsigned int i;
            for (i = 0; i < peerIdListSz; i++) {
                ret = wolfSSL_mcast_peer_add(*ssl, peerIdList[i], 0);
                if (ret != SSL_SUCCESS) {
                    error = 1;
                    WCERR("mcast add peer error");
                    break;
                }
            }
        }
    }

    if (error && *ssl != NULL) {
        wolfSSL_free(*ssl);
    }

    return error;
}


/* WolfcastInit
 * Initializes wolfCast. Sets up the key serivce socket layer. Sets up
 * wolfSSL. Creates the sockets used by either the client or server.
 * Initializes the wolfSSL context, its static memory pool, I/O callbacks
 * as appropriate for NETX or not, multicast ID, and sequence number
 * callback. */
int
WolfcastInit(
        int isClient,
        unsigned short myId,
        WOLFSSL_CTX **ctx,
        SocketInfo_t *si)
{
    int ret, error = 0;

    if (ctx == NULL) {
        error = 1;
        WCERR("WolfcastInit invalid parameters");
    }

    if (!error) {
        ret = KeySocket_Init();
        if (ret != 0) {
            error = 1;
            WCERR("Couldn't initialize key service sockets");
        }
    }

    if (!error) {
    #if defined(DEBUG_WOLFSSL)
        wolfSSL_Debugging_ON();
    #endif

        ret = wolfSSL_Init();
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("couldn't initialize wolfSSL");
        }
    }

    if (!error) {
        error = CreateSockets(si, isClient);
        if (error)
            WCERR("couldn't create sockets");
    }

#ifndef WOLFSSL_STATIC_MEMORY
    if (!error) {
        WOLFSSL_METHOD *method = NULL;
        *ctx = NULL;
        if (isClient) {
            method = wolfDTLSv1_2_client_method();
        }
        else {
            method = wolfDTLSv1_2_server_method();
        }

        if (method != NULL)
            *ctx = wolfSSL_CTX_new(method);

        if (*ctx == NULL) {
            error = 1;
            WCERR("ctx new error");
        }
    }
#else
    if (!error) {
        wolfSSL_method_func method = NULL;
        *ctx = NULL;

        if (isClient)
            method = wolfDTLSv1_2_client_method_ex;
        else
            method = wolfDTLSv1_2_server_method_ex;

        if (method != NULL) {
            ret = wolfSSL_CTX_load_static_memory(
                    ctx, method,
                    memory, sizeof(memory), 0, 1);

            if (ret != SSL_SUCCESS) {
                error = 1;
                WCERR("unable to load static memory and create ctx");
            }
        }
    }

    if (!error) {
        /* load in a buffer for IO */
        ret = wolfSSL_CTX_load_static_memory(
                ctx, NULL, memoryIO, sizeof(memoryIO),
                WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("unable to load static IO memory to ctx");
        }
    }
#endif

    if (!error) {
        ret = wolfSSL_CTX_mcast_set_member_id(*ctx, myId);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set mcast member id error");
        }
    }

    if (!error) {
#ifdef NETX
        wolfSSL_SetIOSend(*ctx, NetxDtlsTxCallback);
        wolfSSL_SetIORecv(*ctx, NetxDtlsRxCallback);
#else
        wolfSSL_SetIORecv(*ctx, BufferDtlsRxCallback);
#endif
    }

    if (!error && isClient) {
        ret = wolfSSL_CTX_mcast_set_highwater_cb(*ctx, 100, 10, 20, seq_cb);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set mcast highwater cb error");
        }
    }

    return error;
}


#ifndef NO_WOLFCAST_CLIENT

typedef struct EpochPeek {
    unsigned char pad[3];
    unsigned char epoch[2];
} EpochPeek;


static unsigned short GetEpoch_ex(const byte *buf)
{
    unsigned short epoch = 0;

    if (buf != NULL) {
        EpochPeek *peek = (EpochPeek*)buf;
        epoch = (peek->epoch[0] << 8) | peek->epoch[1];
    }

    return epoch;
}


#ifdef NETX
static unsigned short GetEpoch(NX_PACKET *packet)
{
    unsigned char buf[sizeof(EpochPeek)];
    ULONG bytesCopied;
    UINT status;
    unsigned short epoch = 0;

    status = nx_packet_data_extract_offset(pkt, 0,
                                           buf, sizeof(buf),
                                           &bytesCopied);

    if (status == NX_SUCCESS && bytesCopied == sizeof(buf)) {
        epoch = GetEpoch_ex(buf);
    }

    return epoch;
}
#else
#define GetEpoch GetEpoch_ex
#endif

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
WolfcastClient(SocketInfo_t *si,
               WOLFSSL *curSsl, WOLFSSL *prevSsl,
               unsigned short curEpoch, unsigned short myId,
               unsigned int *txtime, unsigned int *count)
{
    int error = 0;
    char msg[MSG_SIZE];

    if (curSsl == NULL || txtime == NULL || count == NULL) {
        /* prevSsl is allowed to be NULL, and is checked later. */
        error = 1;
        WCERR("WolfcastClient bad parameters");
    }

    if (!error) {
#ifdef NETX
        UINT n;

        n = nx_udp_socket_receive(si->rxSocket, &nxPacket, NX_NO_WAIT);
        if (n == NX_SUCCESS) {
            WOLFSSL *ssl;
            unsigned short peerId;
            unsigned short epoch;

            epoch = GetEpoch(nxPacket);
            si->rxPacket = nxPacket;
            ssl = (epoch == curEpoch) ? curSsl : prevSsl;

            if (ssl != NULL) {
                n = wolfSSL_mcast_read(ssl, &peerId, msg, MSG_SIZE);
                if (n < 0) {
                    n = wolfSSL_get_error(ssl, n);
                    if (n != SSL_ERROR_WANT_READ) {
                        error = 1;
                        WCERR(wolfSSL_ERR_reason_error_string(n));
                    }
                }
                else
                    WCPRINTF("got msg from peer %u %s\n", peerId, msg);
            }
            else {
                WCPRINTF("Ignoring message from previous Epoch.\n");
            }

            if (si->rxPacket != NULL) {
                ret = nx_packet_release(si->rxPacket);
                if (ret != NX_SUCCESS) {
                    error = 1;
                    WCERR("couldn't release packet");
                }
                si->rxPacket = NULL;
            }
        }
#else
        byte packet[1500];
        ssize_t n;

        n = recvfrom(si->rxFd, packet, sizeof(packet), 0, NULL, 0);
        if (n > 0) {
            WOLFSSL *ssl;
            unsigned short peerId;
            unsigned short epoch;

            si->rxPacket = packet;
            si->rxPacketSz = (unsigned long)n;
            epoch = GetEpoch(packet);
            WCPRINTF("current epoch = %u, received epoch = %u\n", curEpoch, epoch);
            if (epoch == curEpoch)
                ssl = curSsl;
            else if (epoch == curEpoch - 1)
                ssl = prevSsl;
            else
                ssl = NULL;

            if (ssl != NULL) {
                n = wolfSSL_mcast_read(ssl, &peerId, msg, MSG_SIZE);
                if (n < 0) {
                    n = wolfSSL_get_error(ssl, n);
                    if (n != SSL_ERROR_WANT_READ) {
                        error = 1;
                        WCERR(wolfSSL_ERR_reason_error_string(n));
                    }
                }
                else
                    WCPRINTF("got msg from peer %u %s\n", peerId, msg);
            }
            else {
                WCPRINTF("Ignoring message from previous Epoch.\n");
            }
        }
#endif
    }

    if (!error) {
        unsigned int rxtime;

        rxtime = WCTIME();
        if (rxtime >= *txtime) {
            int msg_len;
            int n;

            sprintf(msg, "%u sending message %d", myId, (*count)++);
            msg_len = (int)strlen(msg) + 1;
            n = wolfSSL_write(curSsl, msg, msg_len);
            if (n < 0) {
                error = 1;
                n = wolfSSL_get_error(curSsl, n);
                WCERR(wolfSSL_ERR_reason_error_string(n));
            }
            else
                *txtime = WolfcastClientUpdateTimeout(rxtime);
        }
    }

    return error;
}

#endif


#ifndef NO_WOLFCAST_SERVER

int
WolfcastServer(WOLFSSL *ssl)
{
    int error = 0;

    if (ssl == NULL) {
        error = 1;
        WCERR("WolfcastServer bad parameters");
    }

    if (!error) {
        unsigned int msg_len;
        char msg[80];
        int n;

        sprintf(msg, "time is %us", WCTIME());
        WCPRINTF("sending msg = %s\n", msg);
        msg_len = (unsigned int)strlen(msg) + 1;
        n = wolfSSL_write(ssl, msg, msg_len);
        if (n < 0) {
            error = 1;
            n = wolfSSL_get_error(ssl, n);
            WCERR(wolfSSL_ERR_reason_error_string(n));
        }
    }

    return error;
}

#endif


#ifndef NO_MAIN_DRIVER


static void *
KeyBeaconThreadEntry(void *ignore)
{
    KeyBeacon_Handle_t *h;
    KS_SOCKET_T s = KS_SOCKET_T_INIT;
    int error = 0;
    unsigned short port = SERV_PORT;

    (void)ignore;

    h = KeyBeacon_GetGlobalHandle();
    if (h == NULL) {
        error = 1;
        WCERR("KeyBeacon thread couldn't get global handle.");
    }

    if (!error) {
        struct sockaddr_in bcAddr;
        struct in_addr myAddr;
        int ret;

        memset(&bcAddr, 0, sizeof(bcAddr));
        memset(&myAddr, 0, sizeof(myAddr));
        bcAddr.sin_family = AF_INET;
        bcAddr.sin_port = htons(SERV_PORT);
        bcAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        myAddr.s_addr = inet_addr(LOCAL_ADDR);

        ret = KeySocket_CreateUdpSocket(&s);
        if (ret != 0) {
            error = 1;
        }

        if (!error) {
            ret = KeySocket_Bind(s, &myAddr, ntohs(bcAddr.sin_port));
            if (ret != 0) {
                error = 1;
                WCERR("Cannot bind the key beacon socket.");
            }
        }

        if (!error) {
            int enabled = 1;

    /* enable broadcast */
    KeySocket_SetSockOpt(s, SOL_SOCKET, SO_BROADCAST,
        &enabled, sizeof(enabled));

            ret = KeySocket_SetNonBlocking(s);
            if (ret != 0) {
                error = 1;
                WCERR("Cannot set beacon socket to non-blocking.");
            }
        }

        if (!error) {
            bcAddr.sin_family = AF_INET;
            bcAddr.sin_port = htons(SERV_PORT);
            bcAddr.sin_addr.s_addr = inet_addr("192.168.2.255");
            error = KeyBeacon_SetSocket(h, s,
                                        (struct sockaddr *)&bcAddr,
                                        &myAddr);
            if (error) {
                WCERR("KeyBeacon thread couldn't set the socket.");
            }
        }

        if (!error) {
            error = KeyBeacon_FloatingMaster(h, 0);
            if (error) {
                printf("Couldn't disable floating master\n");
            }
        }

        if (!error) {
            error = KeyBeacon_FindMaster(h);
            if (error) {
                WCERR("KeyBeacon thread can't find the master.");
            }
        }
    }

    while (!error) {
        error = KeyBeacon_Handler(h);
        printf("Key Beacon handler sleeping\n");
        sleep(1);
    }

    if (error) {
        WCERR("KeyBeacon handler cannot run.");
    }

    return NULL;
}


#define PEER_ID_LIST_SZ 99

int
main(
    int argc,
    char** argv)
{
    int error = 0;
    int ret;
    int isClient = 0;
    unsigned short myId;
    unsigned short peerIdList[PEER_ID_LIST_SZ];
    unsigned int peerIdListSz = 0;
    SocketInfo_t si;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *curSsl = NULL;
    WOLFSSL *prevSsl = NULL;
    unsigned short epoch = 0;
    struct in_addr keySrvAddr;
    pthread_t beaconThread;
    KeyBeacon_Handle_t *beacon;

    memset(&keySrvAddr, 0, sizeof(keySrvAddr));

    if (argc == 3 || argc == 4) {
        long n;

        if (strcmp("client", argv[1]) == 0)
            isClient = 1;
        else if (strcmp("server", argv[1]) != 0) {
            error = 1;
            WCERR("type must be either client or server");
        }

        if (!error) {
            if ((isClient && argc != 4) || (!isClient && argc != 3)) {
                error = 1;
                WCPRINTF("Usage: wolfcast client <id> <peer list>\n"
                         "       wolfcast server <id>\n");
            }
        }

        if (!error) {
            n = strtol(argv[2], NULL, 10);
            if (n >= 0 && n < 256)
                myId = n;
            else {
                error = 1;
                WCERR("id must be between 0 and 255, inclusive");
            }
        }

        if (!error && isClient) {
            char *str = argv[3];
            char *endptr = argv[3];

            do {
                if (peerIdListSz == PEER_ID_LIST_SZ) {
                    error = 1;
                    WCERR("too many peer ids");
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
                    WCERR("peer ids must be between 0 and 255, inclusive");
                    break;
                }
            }
            while (*endptr != '\0');
        }
    }
    else {
        error = 1;
        WCPRINTF("Usage: wolfcast client <id> <peer list>\n"
                 "       wolfcast server <id>\n");
    }

    if (!error) {
        beacon = KeyBeacon_GetGlobalHandle();
        if (beacon == NULL) {
            error = 1;
            WCERR("Couldn't get the key beacon handle.");
        }
    }

    if (!error) {
        error = KeyBeacon_Init(beacon);
        if (error) {
            WCERR("Couldn't initialize key beacon.");
        }
    }

    if (!error) {
        if (pthread_create(&beaconThread, NULL,
                           KeyBeaconThreadEntry, NULL) != 0) {
            error = 1;
            WCERR("Couldn't spin up the key beacon thread.");
        }
    }

    if (!error) {
        ret = KeyBeacon_FindMaster(beacon);
        if (ret != 0) {
            error = 1;
            WCERR("Couldn't try to find the master.\n");
        }
    }

    if (!error) {
        do {
            ret = KeyBeacon_GetMaster(beacon, &keySrvAddr);
            if (ret == KB_FM_WAITING) {
                printf("Get Master address sleeping.\n");
                sleep(1);
            }
        } while (ret == KB_FM_WAITING);

        if (ret != 0) {
            error = 1;
            WCERR("Couldn't get the master address.");
        }
    }

    if (!error) {
        error = WolfcastInit(isClient, myId, &ctx, &si);
        if (error) {
            WCERR("Couldn't initialize wolfCast.");
        }
    }

    if (isClient) {
#ifndef NO_WOLFCAST_CLIENT
        unsigned int txtime, count;
        int iteration = 0;

        if (!error)
            error = WolfcastClientInit(&txtime, &count);

        while (!error) {
            fd_set readfds;
            struct timeval timeout = {0, 500000};

            ret = KeyClient_FindMaster(&keySrvAddr, NULL);
            if (ret != 0) {
                error = 1;
                WCERR("unable to find master");
            }

            if (!error) {
                do {
                    ret = KeyBeacon_GetMaster(beacon, &keySrvAddr);
                    if (ret ==  KB_FM_WAITING)
                        sleep(1);
                } while (ret == KB_FM_WAITING);

                if (ret == KB_FM_FAILED) {
                    error = 1;
                    WCERR("unable to get master address");
                }
            }

            if (iteration == 0) {
                WOLFSSL *newSsl;
                KeyRespPacket_t keyResp;
                unsigned short newEpoch;

                iteration = 20;

                if (!error) {
                    ret = KeyClient_GetKey(&keySrvAddr, &keyResp, NULL);
                    if (ret != 0) {
                        error = 1;
                        WCERR("Key retrieval failed");
                    }
                }

                if (!error) {
                    error = WolfcastSessionNew(&newSsl, ctx, &si, 1,
                                               peerIdList, peerIdListSz);

                    if (error || newSsl == NULL) {
                        WCERR("Couldn't create new ssl object.");
                    }
                }

                if (!error) {
                    newEpoch = (keyResp.epoch[0] << 8) | keyResp.epoch[1];
                    WCPRINTF("key set newEpoch = %u\n", newEpoch);
                    ret = wolfSSL_set_secret(newSsl, newEpoch,
                                             keyResp.pms, sizeof(keyResp.pms),
                                             keyResp.clientRandom,
                                    keyResp.serverRandom,
                                    keyResp.suite);
                    if (ret != SSL_SUCCESS) {
                        error = 1;
                        WCERR("Couldn't set the session secret");
                    }
                }

                if (!error) {
                    WCPRINTF("Key has been set.\n");
                    if (prevSsl != NULL)
                        wolfSSL_free(prevSsl);
                    prevSsl = curSsl;
                    curSsl = newSsl;
                    epoch = newEpoch;
                }

                memset(&keyResp, 0, sizeof(keyResp));
            }
            else
                iteration--;

            FD_ZERO(&readfds);
            FD_SET(si.rxFd, &readfds);
            ret = select(si.rxFd+1, &readfds, NULL, NULL, &timeout);
            if (ret < 0) {
                error = 1;
                WCERR("main select failed");
                break;
            }

            if (FD_ISSET(si.rxFd, &readfds)) {
                error = WolfcastClient(&si,
                                       curSsl, prevSsl,
                                       epoch, myId,
                                       &txtime, &count);
            }
        }
#else
        error = 1;
#endif
    }
    else {
#ifndef NO_WOLFCAST_SERVER
        {
            WOLFSSL *newSsl;
            KeyRespPacket_t keyResp;
            unsigned short newEpoch;

            if (!error) {
                ret = KeyClient_GetKey(&keySrvAddr, &keyResp, NULL);
                if (ret != 0) {
                    error = 1;
                    WCERR("Key retrieval failed");
                }
            }

            if (!error) {
                error = WolfcastSessionNew(&newSsl, ctx, &si, 0, NULL, 0);

                if (error || newSsl == NULL) {
                    WCERR("Couldn't create new ssl object.");
                }
            }

            if (!error) {
                newEpoch = (keyResp.epoch[0] << 8) | keyResp.epoch[1];
                ret = wolfSSL_set_secret(newSsl, newEpoch,
                                keyResp.pms, sizeof(keyResp.pms),
                                keyResp.clientRandom, keyResp.serverRandom,
                                keyResp.suite);
                if (ret != SSL_SUCCESS) {
                    error = 1;
                    WCERR("Couldn't set the session secret");
                }
                else {
                    WCPRINTF("Key has been set.\n");
                    if (prevSsl != NULL)
                        wolfSSL_free(prevSsl);
                    prevSsl = curSsl;
                    curSsl = newSsl;
                    epoch = newEpoch;
                }
            }

            memset(&keyResp, 0, sizeof(keyResp));
        }

        while (!error) {
            error = WolfcastServer(curSsl);
            sleep(1);
        }
#else
        error = 1;
#endif
    }

    return error;
}

#endif /* NO_MAIN_DRIVER */
