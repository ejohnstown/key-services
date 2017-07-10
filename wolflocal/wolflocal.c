#include "types.h"
#include "wolflocal.h"
#if 0
#include "benchmark.h"
#include "wolftest.h"
#endif
#include "key-services.h"
#include "wolfcast.h"
#include <wolfssl/error-ssl.h>


/* mySeed() and LowResTimer() are application defined functions
 * needed by wolfSSL. */
int mySeed(unsigned char* output, unsigned int sz)
{
    unsigned int i;

    srand(bsp_fast_timer_uptime());
    for (i = 0; i < sz; i++ ) {
        output[i] = rand() % 256;
        if ((i % 8) == 7) {
            srand(bsp_fast_timer_uptime());
        }
    }

    return 0;
}


unsigned int LowResTimer(void)
{
    return(tx_time_get() / 100);
}


/* The rest of this file is the start up code and entry points for the
 * threads used to demonstrate the DTLS Multicast. */

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#ifndef WOLFLOCAL_LOGGING_LEVEL
    #define WOLFLOCAL_LOGGING_LEVEL 0
#endif

#define KS_PRINTF bsp_debug_printf

#define KS_MEMORY_POOL_SZ 4096
#define KS_STACK_SZ 4096
#define KS_PRIORITY 15
#define KS_THRESHOLD 15

#define KS_TIMEOUT_1SEC 100
#define KS_TIMEOUT_NETWORK_READY KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_CLIENT KS_TIMEOUT_1SEC
#define KS_TIMEOUT_WOLFLOCAL_KEY_POLL KS_TIMEOUT_1SEC
#define KS_TIMEOUT_WOLFCAST KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_STATE_WRITE TX_WAIT_FOREVER
#define KS_TIMEOUT_KEY_STATE_READ TX_NO_WAIT
#define KS_TIMEOUT_HEAP_INIT KS_TIMEOUT_1SEC

#define SERVER_ID 5
#define FOREIGN_CLIENT_ID 23
#ifdef PGB000
    #define CLIENT_ID 6
    #define OTHER_CLIENT_ID 7
#else /* PGB006 */
    #define CLIENT_ID 7
    #define OTHER_CLIENT_ID 6
#endif

#ifndef WOLFLOCAL_KEY_SWITCH_TIME
    #define WOLFLOCAL_KEY_SWITCH_TIME 15
#endif
#ifndef WOLFLOCAL_KEY_CHANGE_PERIOD
    #define WOLFLOCAL_KEY_CHANGE_PERIOD 60
#endif
#ifndef WOLFLOCAL_TIMER_HOLDOFF
    #define WOLFLOCAL_TIMER_HOLDOFF 20
#endif


#ifdef PGB000
    #include "pgb000_com.h"
#else /* PGB000:PGB002 */
    #include "pgb002_ap2.h"
#endif

/* Note: Return codes for wolfSSL code are of type int and typically
 * named "result". Return codes for ThreadX/NetX are of type UINT
 * and typically named "status". */

static TX_THREAD gKeyBcastUdpThread;
static TX_THREAD gKeyClientThread;
static TX_THREAD gWolfCastClientThread[3];
static TX_THREAD gKeyServerThread;

static char gKeyBcastUdpStack[KS_STACK_SZ];
static char gKeyClientStack[KS_STACK_SZ];
static char gWolfCastClientStack[3][KS_STACK_SZ];
static char gKeyServerStack[KS_STACK_SZ];
static unsigned char gKeyServiceMemory[KS_MEMORY_POOL_SZ];

#ifdef WOLFSSL_STATIC_MEMORY
    #if defined(NETX) && defined(PGB002)
        #define MEMORY_SECTION LINK_SECTION(data_sdram)
    #else
        #define MEMORY_SECTION
    #endif
    MEMORY_SECTION unsigned char gWolfCastMemory[3][WOLFLOCAL_STATIC_MEMORY_SZ];
#endif


/* Mutex for controlling the current key state. The Key
 * Client thread will be writing to the key state and
 * the wolfCast client will be reading it. Also, the
 * wolfCast client will set a semaphore to for the Key
 * Client to request a new key. */
static TX_MUTEX gKeyStateMutex;
static UINT gKeySet[3] = { 0, 0, 0 };
UINT gGetNewKey = 1;
UINT gRequestRekey = 0;
static UINT gFindMaster = 1;
UINT gSwitchKeys[3] = { 1, 1, 1 };
static KeyRespPacket_t gKeyState;
static WOLFSSL_HEAP_HINT *gHeapHint = NULL;
static struct in_addr gKeySrvAddr = { 0 };
static UINT gRekeyPending = 0;
static UINT gSwitchKeyCount = 0;
wolfWrapper_t gWrappers[3];
ULONG gAddr = 0;
ULONG gMask = 0;

/* Group address for the wolfCast multicast group. */
static struct in_addr gGroupAddr = { .s_addr = 0xE2000003 };

/* Port number for the wolfCast multicast group. */
static unsigned short gGroupPort = 12345;

/* Port number for the KeyBcast server all endpoints run. */
static unsigned short gBcastPort = 22222;

/* Port number for the KeyServer all endpoints run. */
static unsigned short gServPort = 11111;


const USHORT gPeerIdList[] = { SERVER_ID, FOREIGN_CLIENT_ID, OTHER_CLIENT_ID };
#define PEER_ID_LIST_SZ (sizeof(gPeerIdList)/sizeof(gPeerIdList[0]))


extern NX_IP* nxIp;
extern unsigned short gKeyServerEpoch;
extern unsigned char gPeerId;


static int isAddrSet(void)
{
    int isSet = 0;
    UINT status;
    ULONG addr, mask;

    if (nxIp) {
        status = nx_ip_address_get(nxIp, &addr, &mask);
        if (status == NX_SUCCESS && addr != 0 &&
            ((addr & 0xFFFF0000UL) != IP_ADDRESS(169,254,0,0))) {

            gAddr = addr;
            gMask = mask;
            isSet = 1;
        }
    }

    return isSet;
}


static int isNetworkReady(void)
{
    int isReady = 0;

    if (gAddr != 0)
        isReady = 1;

    return isReady;
}


static void
keyServerCb(CmdPacket_t* pkt)
{
    if (pkt &&
        (pkt->header.type == CMD_PKT_TYPE_KEY_NEW ||
         (pkt->header.type == CMD_PKT_TYPE_KEY_REQ &&
          !gRekeyPending &&
          (wolfSSL_mcast_peer_known(gWrappers[0].curSsl, pkt->header.id) ||
           wolfSSL_mcast_peer_known(gWrappers[1].curSsl, pkt->header.id) ||
           wolfSSL_mcast_peer_known(gWrappers[2].curSsl, pkt->header.id))))) {

        gRekeyPending = 1;
        gSwitchKeyCount = WOLFLOCAL_KEY_SWITCH_TIME;
        KeyServer_GenNewKey(gHeapHint);
    }
}


/* KeyServerEntry
 * Thread entry point to drive the key server. Key server really
 * shouldn't ever return, but the return code is checked and
 * reported, just in case. */
static void
KeyServerEntry(ULONG ignore)
{
    int result;

    (void)ignore;

    if (wolfSSL_Init() != SSL_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("KeyServer couldn't initialize wolfSSL.\n");
#endif
    }

    while (!isAddrSet()) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("Key server waiting for network.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_NETWORK_READY);
    }

    while (gHeapHint == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
        KS_PRINTF("KeyServer waiting for heap.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_HEAP_INIT);
    }

    {
        struct in_addr inaddr = { .s_addr = gAddr };
        result = KeyServer_Init(gHeapHint, &inaddr, gBcastPort, gServPort);
    }
    if (result != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("KeyServer couldn't initialize. (%d)\n", result);
#endif
    }

    if (result == 0) {
#ifdef WOLFLOCAL_TEST_KEY_SERVER
        KeyServer_Resume();
#endif
        result = KeyServer_Run(keyServerCb, gHeapHint);
        if (result != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
            KS_PRINTF("KeyServer terminated. (%d)\n", result);
#endif
        }
    }

    KeyServer_Free(gHeapHint);
    wolfSSL_Cleanup();
}


static void
broadcastCb(CmdPacket_t* pkt)
{
    unsigned char* msg;
    unsigned short epoch;

    if (KeyServer_IsRunning()) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("I am the key server, I should ignore my broadcasts.\n");
#endif
        return;
    }

    if (pkt != NULL) {
        switch (pkt->header.type) {
            case CMD_PKT_TYPE_KEY_CHG:
                /* trigger key change */
                msg = pkt->msg.keyChgResp.ipaddr;
                XMEMCPY(&gKeySrvAddr.s_addr, msg, sizeof(gKeySrvAddr.s_addr));
                gGetNewKey = 1;
                break;
            case CMD_PKT_TYPE_KEY_USE:
                /* switch to new key */
                msg = pkt->msg.epochResp.epoch;
                epoch = (msg[0] << 8) | msg[1];
                if (epoch != gKeyServerEpoch) {
                    gSwitchKeys[0] = epoch;
                    gSwitchKeys[1] = epoch;
                    gSwitchKeys[2] = epoch;
                }
                break;
        }
    }
}


/* KeyBcastUdpEntry
 * Thread entry point to drive the UDP beacon. This really shouldn't
 * ever return, but the return code is checked and reported, just in
 * case. First it waits for the network interface to become ready,
 * then it calls the self-contained KeyBcast's UDP server, which
 * handles the beacon. */
static void
KeyBcastUdpEntry(ULONG ignore)
{
    int result;

    (void)ignore;

    while (!isNetworkReady()) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("Key Service bcast udp server waiting for network.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_NETWORK_READY);
    }

    while (gHeapHint == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
        KS_PRINTF("KeyBcast waiting for heap.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_HEAP_INIT);
    }

    result = KeyBcast_RunUdp(&gKeySrvAddr, broadcastCb, gHeapHint);
    if (result != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
        KS_PRINTF("KeyBcastUdp terminated. (%d)\n", result);
#endif
    }
}


/* KeyClientEntry
 * Thread entry point to drive the key client. It initializes wolfSSL for
 * its use, waits for the network interface to be ready, then it loops
 * trying to get key updates. */
static void
KeyClientEntry(ULONG ignore)
{
    int result;
    UINT findMaster = 0;
    UINT requestRekey = 0;
    UINT getNewKey = 0;
    UINT storeKey = 0;
    UINT status = TX_SUCCESS;
    KeyRespPacket_t keyResp;

    (void)ignore;

    result = wolfSSL_Init();
    if (result != SSL_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("KeyClient couldn't initialize wolfSSL. (%d)\n", result);
#endif
        return;
    }

    while (!isNetworkReady()) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
        KS_PRINTF("Key Service client waiting for IP Address.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_NETWORK_READY);
    }

    while (gHeapHint == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
        KS_PRINTF("KeyClient waiting for heap.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_HEAP_INIT);
    }

    while (1) {
        if (!findMaster && !requestRekey && !getNewKey && !storeKey) {
            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_READ);
            if (status == TX_SUCCESS) {
                findMaster = gFindMaster;
                gFindMaster = 0;
                getNewKey = gGetNewKey;
                gGetNewKey = 0;
                requestRekey = gRequestRekey;
                gRequestRekey = 0;
                tx_mutex_put(&gKeyStateMutex);
            }
            else {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
                KS_PRINTF("Couldn't get key state mutex to read\n");
#endif
            }
        }

        if (findMaster) {
            result = KeyClient_FindMaster(&gKeySrvAddr, gHeapHint);
            if (result != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
                KS_PRINTF("Key server didn't announce itself.\n");
#endif
            }
            else {
                findMaster = 0;
            }
        }

        if (!findMaster && requestRekey && !storeKey) {
            EpochRespPacket_t epochResp;
            result = KeyClient_NewKeyRequest(&gKeySrvAddr, &epochResp, gHeapHint);
            if (result) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
                KS_PRINTF("Failed to request new key.\n");
#endif
            }
            else {
                requestRekey = 0;
#if WOLFLOCAL_LOGGING_LEVEL >= 1
                KS_PRINTF("New epoch will be %u.\n",
                          ((epochResp.epoch[0] << 8) | epochResp.epoch[1]));
#endif
            }
        }

        if (!findMaster && getNewKey && !storeKey) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
            KS_PRINTF("Key client getting key.\n");
#endif
            result = KeyClient_GetKey(&gKeySrvAddr, &keyResp, gHeapHint);
            if (result != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
                KS_PRINTF("Unable to retrieve key\n");
#endif
            }
            else {
                getNewKey = 0;
                storeKey = 1;
            }
        }

        if (storeKey) {
            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_WRITE);
            if (status == TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
                KS_PRINTF("Key client got key\n");
#endif
                memcpy(&gKeyState, &keyResp, sizeof(KeyRespPacket_t));
                gKeySet[0] = 1;
                gKeySet[1] = 1;
                gKeySet[2] = 1;
                storeKey = 0;
                tx_mutex_put(&gKeyStateMutex);
            }
            else {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
                KS_PRINTF("Couldn't get key state mutex to write\n");
#endif
            }
        }

        tx_thread_sleep(KS_TIMEOUT_KEY_CLIENT);
    }
}


/* WolfCastClientEntry
 * Thread entry point to drive the wolfCast client. This wraps
 * the old chunk of code from test.c that was executed in the
 * the test_1hz() thread. The old globals used by the code are
 * now local variables. It will wait for the flag for the key
 * getting set to go true before starting to broadcast. */
static void
WolfCastClientEntry(ULONG streamId)
{
    wolfWrapper_t* wrapper;
    unsigned int txTime;
    unsigned int txCount;
    int error;

    while (!isNetworkReady()) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("wolfCast thread %u waiting for network.\n", streamId);
#endif
        tx_thread_sleep(KS_TIMEOUT_NETWORK_READY);
    }

    wrapper = &gWrappers[streamId];

    error = wolfWrapper_Init(wrapper, streamId, gPeerId,
                             gGroupPort + streamId, gGroupAddr.s_addr,
                             gPeerIdList, PEER_ID_LIST_SZ,
                             gWolfCastMemory[streamId],
                             sizeof(gWolfCastMemory[streamId]));

    if (!error)
        error = WolfcastClientInit(&txTime, &txCount);

    while (!error) {
        error = wolfWrapper_Update(wrapper);
        if (!error)
            error = WolfcastClient(wrapper, &txTime, &txCount);
        if (!error)
            tx_thread_sleep(KS_TIMEOUT_WOLFCAST);
    }

#if WOLFLOCAL_LOGGING_LEVEL >= 3
    KS_PRINTF("wolfCast thread %u ended.\n", streamId);
#endif
}


/* WolfLocalInit
 * Runs the wolfCrypt test and benchmark. Sets up the mutex for the
 * group key access. Creates threads for the Key Server, Key Client,
 * and the wolfCast demo application. */
void
WolfLocalInit(void)
{
    UINT status;
    int i;

#if 0
    /* The wolfcrypt_test() and benchmark_test() are currently removed.
     * The wolfcrypt_test() causes trouble with the RX board. It uses
     * too much memory on the stack to perform the memory test, and the
     * cipher tests use 30k of global data at startup and keeps it
     * forever. */
    wolfcrypt_test(NULL);
    benchmark_test(NULL);
#endif

    gPeerId = CLIENT_ID;

    if (KeySocket_Init() != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("couldn't initialize the KeySocket\n");
#endif
        return;
    }

    status = tx_mutex_create(&gKeyStateMutex, "key state mutex",
                             TX_NO_INHERIT);
    if (status != TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("key state mutex create failed = 0x%02X\n", status);
#endif
        return;
    }

    status = wc_LoadStaticMemory(&gHeapHint,
                                 gKeyServiceMemory, sizeof(gKeyServiceMemory),
                                 WOLFMEM_GENERAL, 1);
    if (status != 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("WolfLocalInit couldn't get memory pool. (%d)\n", status);
#endif
    }

    status = tx_thread_create(&gKeyBcastUdpThread,
                              "key service bcast udp server",
                              KeyBcastUdpEntry, 0,
                              gKeyBcastUdpStack, sizeof(gKeyBcastUdpStack),
                              KS_PRIORITY, KS_THRESHOLD,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("key server bcast udp thread create failed = 0x%02X\n",
                  status);
#endif
        return;
    }

    status = tx_thread_create(&gKeyServerThread, "key service server",
                           KeyServerEntry, 0,
                           gKeyServerStack, sizeof(gKeyServerStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("key server thread create failed = 0x%02X\n", status);
#endif
        return;
    }

    status = tx_thread_create(&gKeyClientThread, "key service client",
                           KeyClientEntry, 0,
                           gKeyClientStack, sizeof(gKeyClientStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("key client thread create failed = 0x%02X\n", status);
#endif
        return;
    }

    for (i = 0; i < 3; i++) {
        status = tx_thread_create(&gWolfCastClientThread[i], "wolfCast client",
                               WolfCastClientEntry, i,
                               gWolfCastClientStack[i],
                               sizeof(gWolfCastClientStack[i]),
                               KS_PRIORITY, KS_THRESHOLD,
                               TX_NO_TIME_SLICE, TX_AUTO_START);
        if (status != TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
            KS_PRINTF("wolfCast client thread %u create failed = 0x%02X\n",
                      i, status);
#endif
            return;
        }
    }

    return;
}


void WolfLocalTimer(void)
{
    static unsigned int count = 0;
    UINT status;
    int ret;

    (void)status;
    (void)ret;

    count++;

    /* Give it a X count before trying to do anything. */
    if (count > WOLFLOCAL_TIMER_HOLDOFF) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("timer: %u\n", count);
#endif
        /* Every X seconds on the 0, ... */
        if ((count % WOLFLOCAL_KEY_CHANGE_PERIOD) == 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
            KS_PRINTF("timer: %u on the 0\n", WOLFLOCAL_KEY_CHANGE_PERIOD);
#endif
            if (KeyServer_IsRunning()) {
                if (!gRekeyPending) {
                    ret = KeyServer_GenNewKey(gHeapHint);
                    if (ret) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
                        KS_PRINTF("Failed to announce new key.\n");
#endif
                    }
                    else {
                        status = tx_mutex_get(&gKeyStateMutex,
                                              KS_TIMEOUT_KEY_STATE_WRITE);
                        if (status == TX_SUCCESS) {
                            gGetNewKey = 1;
                            gRekeyPending = 1;
                            gSwitchKeyCount = WOLFLOCAL_KEY_SWITCH_TIME;
                            tx_mutex_put(&gKeyStateMutex);
                        }
                    }
                }
            }
            else {
#ifdef WOLFLOCAL_TEST_KEY_REQUEST
                status = tx_mutex_get(&gKeyStateMutex,
                                      KS_TIMEOUT_KEY_STATE_WRITE);
                if (status == NX_SUCCESS) {
                    gRequestRekey = 1;
                    tx_mutex_put(&gKeyStateMutex);
                }
#endif /* WOLFLOCAL_TEST_KEY_REQUEST */
            }
        }

        /* If the switch key count is set, decrement it. If it becomes 0,
         * switch the keys. */
        if (gSwitchKeyCount) {
            gSwitchKeyCount--;
            if (gSwitchKeyCount == 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
                KS_PRINTF("timer: 15 seconds later\n");
#endif
                if (KeyServer_IsRunning()) {
                    ret = KeyServer_NewKeyUse(gHeapHint);
                    if (ret) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
                        KS_PRINTF("Failed to announce key switch.\n");
#endif
                    }
                    else {
                        status = tx_mutex_get(&gKeyStateMutex,
                                              KS_TIMEOUT_KEY_STATE_WRITE);
                        if (status == TX_SUCCESS) {
                            gSwitchKeys[0] = gKeyServerEpoch;
                            gSwitchKeys[1] = gKeyServerEpoch;
                            gSwitchKeys[2] = gKeyServerEpoch;
                            /* Should be an epoch number */
                            gRekeyPending = 0;
                            tx_mutex_put(&gKeyStateMutex);
                        }
                    }
                }
            }
        }
    }
}


static int
NetxDtlsTxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void* ctx)
{
    wolfWrapper_t* wrapper;
    NX_PACKET *pkt = NULL;
    UINT status;

    (void)ssl;

    if (ctx == NULL || buf == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("transmit callback invalid parameters\n");
#endif
        goto exit;
    }
    wrapper = (wolfWrapper_t*)ctx;

    status = nx_packet_allocate(wrapper->pool, &pkt,
                                NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("couldn't allocate packet wrapper\n");
#endif
        goto exit;
    }

    status = nx_packet_data_append(pkt, buf, sz,
                                   wrapper->pool, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("couldn't append data to packet\n");
#endif
        goto exit;
    }

    status = nx_udp_socket_send(&wrapper->realTxSocket, pkt,
                                wrapper->groupAddr, wrapper->groupPort);
    if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("tx error\n");
#endif
        goto exit;
    }

exit:
    if (status != NX_SUCCESS) {
        sz = WOLFSSL_CBIO_ERR_GENERAL;

        /* In case of error, release packet. */
        status = nx_packet_release(pkt);
        if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
            KS_PRINTF("couldn't release packet\n");
#endif
        }
    }

    return sz;
}


static int
NetxDtlsRxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void* ctx)
{
    wolfWrapper_t* wrapper;
    NX_PACKET *pkt;
    UINT status;
    unsigned long rxSz;

    (void)ssl;

    if (ctx == NULL || buf == NULL || sz <= 0) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("receive callback invalid parameters\n");
#endif
        goto exit;
    }

    wrapper = (wolfWrapper_t*)ctx;
    pkt = wrapper->rxPacket;
    if (pkt == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("no packet\n");
#endif
        status = NX_NO_PACKET;
        goto exit;
    }

    status = nx_packet_length_get(pkt, &rxSz);
    if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("couldn't get packet length\n");
#endif
        goto exit;
    }

    if (rxSz > (unsigned long)sz) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("receive packet too large for buffer\n");
#endif
        goto exit;
    }

    status = nx_packet_data_retrieve(pkt, buf, &rxSz);
    if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("couldn't retrieve packet\n");
#endif
        goto exit;
    }

exit:
    if (status == NX_SUCCESS)
        sz = (int)rxSz;
    else if (status == NX_NO_PACKET)
        sz = WOLFSSL_CBIO_ERR_WANT_READ;
    else
        sz = WOLFSSL_CBIO_ERR_GENERAL;

    if (pkt != NULL) {
        status = nx_packet_release(pkt);
        if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
            KS_PRINTF("couldn't release packet\n");
#endif
        }
        else
            wrapper->rxPacket = NULL;
    }

    return sz;
}



int wolfWrapper_Init(wolfWrapper_t* wrapper, UINT streamId,
                     UCHAR myId, USHORT groupPort, ULONG groupAddr,
                     const USHORT *peerIdList, UINT peerIdListSz,
                     void* heap, UINT heapSz)
{
    int ret;
    int keySet = 0;

    if (wrapper == NULL || heap == NULL || heapSz == 0 ||
        peerIdList == NULL || peerIdListSz == 0 ||
        groupAddr == 0 || groupPort == 0) {

        goto exit;
    }

    memset(wrapper, 0, sizeof(wolfWrapper_t));

    wrapper->streamId = streamId;
    wrapper->myId = myId;
    wrapper->groupAddr = groupAddr;
    wrapper->groupPort = groupPort;
    wrapper->peerIdList = peerIdList;
    wrapper->peerIdListSz = peerIdListSz;
    wrapper->txSocket = (KS_SOCKET_T)&wrapper->realTxSocket;
    wrapper->rxSocket = (KS_SOCKET_T)&wrapper->realRxSocket;
#ifdef PGB000
    wrapper->ip = &bsp_ip_system_bus;
    wrapper->pool = &bsp_pool_system_bus;
#else /* PGB000:PGB002 */
    wrapper->ip = &bsp_ip_local_bus;
    wrapper->pool = &bsp_pool_local_bus;
#endif /* PGB002 */

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("wolfWrapper_Init couldn't initialize wolfSSL\n");
#endif
        goto exit;
    }

    ret = wolfSSL_CTX_load_static_memory(&wrapper->ctx,
                                         wolfDTLSv1_2_client_method_ex,
                                         heap, heapSz, 0, 2);
    if (ret != SSL_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("unable to load static memory and create ctx\n");
#endif
        goto exit;
    }

    wolfSSL_SetIOSend(wrapper->ctx, NetxDtlsTxCallback);
    wolfSSL_SetIORecv(wrapper->ctx, NetxDtlsRxCallback);
    ret = wolfSSL_CTX_mcast_set_member_id(wrapper->ctx, myId);
    if (ret != SSL_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("set mcast member id error\n");
#endif
        goto exit;
    }

    ret = nx_udp_enable(wrapper->ip);
    if (ret == NX_ALREADY_ENABLED) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("UDP already enabled\n");
#endif
    }
    else if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("cannot enable UDP\n");
#endif
        goto exit;
    }

    ret = nx_igmp_enable(wrapper->ip);
    if (ret == NX_ALREADY_ENABLED) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("IGMP already enabled\n");
#endif
    }
    else if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("cannot enable IGMP\n");
#endif
        goto exit;
    }

    ret = nx_udp_socket_create(wrapper->ip, &wrapper->realTxSocket,
                               "Multicast TX Socket",
                               NX_IP_NORMAL, NX_DONT_FRAGMENT,
                               NX_IP_TIME_TO_LIVE, 30);
    if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("unable to create tx socket\n");
#endif
        goto exit;
    }

    ret = nx_udp_socket_bind(&wrapper->realTxSocket, NX_ANY_PORT, NX_NO_WAIT);
    if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("tx bind failed\n");
#endif
        goto exit;
    }

    ret = nx_igmp_loopback_disable(wrapper->ip);

    if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("couldn't disable multicast loopback\n");
#endif
        goto exit;
    }

    ret = nx_udp_socket_create(wrapper->ip, &wrapper->realRxSocket,
                               "Multicast RX Socket",
                               NX_IP_NORMAL, NX_DONT_FRAGMENT,
                               NX_IP_TIME_TO_LIVE, 30);
    if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("unable to create rx socket\n");
#endif
        goto exit;
    }

    ret = nx_udp_socket_bind(&wrapper->realRxSocket,
                             wrapper->groupPort, NX_NO_WAIT);
    if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("rx bind failed\n");
#endif
        goto exit;
    }

    ret = nx_igmp_multicast_join(wrapper->ip, wrapper->groupAddr);
    if (ret != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("setsockopt mc add membership failed\n");
#endif
        goto exit;
    }

    /* Wait for the first key. */
    while (!keySet) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("wolfCast thread waiting for first key.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_WOLFLOCAL_KEY_POLL);

        ret = tx_mutex_get(&gKeyStateMutex, TX_WAIT_FOREVER);
        if (ret == TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
            KS_PRINTF("wolfCast getting key set flag\n");
#endif
            keySet = gKeySet[streamId];
            ret = tx_mutex_put(&gKeyStateMutex);
        }
        else {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
            KS_PRINTF("Couldn't get key mutex. Trying again.\n");
#endif
        }
    }
    gSwitchKeys[streamId] = (gKeyState.epoch[0] << 8) | gKeyState.epoch[1];

exit:
    return ret;
}


static int wolfWrapper_NewSession(wolfWrapper_t* wrapper, WOLFSSL** ssl)
{
    int ret = SSL_SUCCESS;
    UINT i;
    WOLFSSL* newSsl = NULL;

    if (wrapper == NULL || ssl == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("wolfWrapper_NewWrapper invalid parameters\n");
#endif
        goto exit;
    }

    newSsl = wolfSSL_new(wrapper->ctx);
    if (newSsl == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("ssl new error\n");
#endif
        goto exit;
    }

    wolfSSL_SetIOWriteCtx(newSsl, wrapper);
    wolfSSL_SetIOReadCtx(newSsl, wrapper);
    wolfSSL_set_using_nonblock(newSsl, 1);

    for (i = 0; i < wrapper->peerIdListSz; i++) {
        ret = wolfSSL_mcast_peer_add(newSsl, wrapper->peerIdList[i], 0);
        if (ret != SSL_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
            KS_PRINTF("mcast add peer error\n");
#endif
            goto exit;
        }
    }
    
    *ssl = newSsl;
    newSsl = NULL;

exit:
    if (newSsl)
        wolfSSL_free(newSsl);

    return (ret != SSL_SUCCESS);
}


int wolfWrapper_Update(wolfWrapper_t* wrapper)
{
    UINT status;
    int error = 0;

    if (wrapper == NULL) {
        error = 1;
        goto exit;
    }

    if (!wrapper->keySet && !wrapper->switchKeys) {
        status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_READ);
        if (status != TX_SUCCESS)
            goto exit;

        wrapper->keySet = gKeySet[wrapper->streamId];
        gKeySet[wrapper->streamId] = 0;
        wrapper->switchKeys = gSwitchKeys[wrapper->streamId];
        gSwitchKeys[wrapper->streamId] = 0;

        if (wrapper->keySet) {
            memcpy(&wrapper->keyState, &gKeyState, sizeof(gKeyState));
        }

        status = tx_mutex_put(&gKeyStateMutex);
        if (status != TX_SUCCESS) {
            error = 1;
            goto exit;
        }
    }

    if (wrapper->keySet) {
        wrapper->keySet = 0;
        wrapper->newEpoch = (wrapper->keyState.epoch[0] << 8) |
                            wrapper->keyState.epoch[1];
    }

    if (wrapper->switchKeys) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("switchKeys = %u, newEpoch = %u, epoch = %u\n",
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
#if WOLFLOCAL_LOGGING_LEVEL >= 1
                KS_PRINTF("Couldn't set the session secret\n");
#endif
                goto exit;
            }
            memset(&wrapper->keyState, 0, sizeof(wrapper->keyState));

            if (wrapper->prevSsl != NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
                KS_PRINTF("Releasing old session.\n");
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
#if WOLFLOCAL_LOGGING_LEVEL >= 3
            KS_PRINTF("Spurious key switch, ignoring.\n");
#endif
        }
        else {
#if WOLFLOCAL_LOGGING_LEVEL >= 2
            KS_PRINTF("Missed a key change.\n");
#endif
            gGetNewKey = 1;
        }

        wrapper->switchKeys = 0;
    }

exit:
    return error;
}


typedef struct EpochPeek {
    unsigned char pad[3];
    unsigned char epoch[2];
} EpochPeek;


static unsigned short GetEpoch(NX_PACKET *packet)
{
    unsigned char buf[sizeof(EpochPeek)];
    ULONG bytesCopied;
    UINT status;
    unsigned short epoch = 0;

    status = nx_packet_data_extract_offset(packet, 0,
                                           buf, sizeof(buf),
                                           &bytesCopied);

    if (status == NX_SUCCESS && bytesCopied == sizeof(buf)) {
        EpochPeek *peek = (EpochPeek*)buf;

        epoch = (peek->epoch[0] << 8) | peek->epoch[1];
    }

    return epoch;
}


int wolfWrapper_Write(wolfWrapper_t* wrapper, const void* buf, int sz)
{
    int sentSz = 0;
/* If there isn't a curSsl, return want write? */
    if (wrapper == NULL || buf == NULL || sz == 0)
        goto exit;

    sentSz = wolfSSL_write(wrapper->curSsl, buf, sz);
    if (sentSz < 0) {
        sentSz = wolfSSL_get_error(wrapper->curSsl, sentSz);
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("wolfSSL error: %s\n",
                  wolfSSL_ERR_reason_error_string(sentSz));
#endif
    }

exit:
    return sentSz;
}


int wolfWrapper_Read(wolfWrapper_t* wrapper, USHORT* peerId,
                   void* buf, int sz)
{
    UINT status;
    NX_PACKET *nxPacket = NULL;
    WOLFSSL *ssl = NULL;
    unsigned short epoch;
    int recvSz = 0;

    if (wrapper == NULL || buf == NULL || sz == 0)
        goto exit;

    status = nx_udp_socket_receive(&wrapper->realRxSocket,
                                   &nxPacket, NX_NO_WAIT);
    if (status != NX_SUCCESS)
        goto exit;

    wrapper->rxPacket = nxPacket;
    epoch = GetEpoch(nxPacket);
    if (epoch == wrapper->epoch)
        ssl = wrapper->curSsl;
    else if (epoch < wrapper->epoch)
        ssl = wrapper->prevSsl;
    else if (epoch > wrapper->epoch) {
        /* We may have missed a new key update or a switch keys. */
        gSwitchKeys[0] = epoch;
        gSwitchKeys[1] = epoch;
        gSwitchKeys[2] = epoch;
    }

    if (ssl == NULL) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
        KS_PRINTF("Ignoring message unknown Epoch.\n");
#endif
        goto exit;
    }

    recvSz = wolfSSL_mcast_read(ssl, peerId, buf, sz);
    if (recvSz < 0) {
        recvSz = wolfSSL_get_error(ssl, recvSz);
        if (recvSz == VERIFY_MAC_ERROR || recvSz == DECRYPT_ERROR) {
#if WOLFLOCAL_LOGGING_LEVEL >= 3
            KS_PRINTF("Allowable DTLS error. Ignoring a message.\n");
#endif
        }
        else if (recvSz != SSL_ERROR_WANT_READ) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
            KS_PRINTF("wolfSSL error: %s\n",
                      wolfSSL_ERR_reason_error_string(recvSz));
#endif
            goto exit;
        }
    }

exit:
    if (wrapper->rxPacket != NULL) {
        status = nx_packet_release(wrapper->rxPacket);
        if (status != NX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
            KS_PRINTF("couldn't release packet\n");
#endif
        }
        wrapper->rxPacket = NULL;
    }

    return recvSz;
}
