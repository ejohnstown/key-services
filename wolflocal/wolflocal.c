#include "types.h"
#include "wolflocal.h"
#include "benchmark.h"
#include "wolftest.h"
#include "key-services.h"
#include "wolfcast.h"


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

#define KS_PRINTF bsp_debug_printf
#define KS_STACK_SZ (6 * 1024)
#define KS_PRIORITY 15
#define KS_THRESHOLD 15
#define KS_MEMORY_POOL_SZ KS_STACK_SZ

#define KS_TIMEOUT_1SEC 100
#define KS_TIMEOUT_NETWORK_READY KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_CLIENT KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_SERVER KS_TIMEOUT_1SEC
#define KS_TIMEOUT_WOLFCAST_KEY_POLL KS_TIMEOUT_1SEC
#define KS_TIMEOUT_WOLFCAST KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_STATE_WRITE TX_WAIT_FOREVER
#define KS_TIMEOUT_KEY_STATE_READ TX_NO_WAIT

#define SERVER_ID 5
#define FOREIGN_CLIENT_ID 23
#ifdef PGB000
    #define CLIENT_ID 6
    #define OTHER_CLIENT_ID 7
#else /* PGB006 */
    #define CLIENT_ID 7
    #define OTHER_CLIENT_ID 6
#endif


/* Note: Return codes for wolfSSL code are of type int and typically
 * named "result". Return codes for ThreadX/NetX are of type UINT
 * and typically named "status". */

static TX_THREAD gKeyServerThread;
static TX_THREAD gKeyServerUdpThread;
static TX_THREAD gKeyClientThread;
static TX_THREAD gWolfCastClientThread;

static char gKeyServerStack[KS_STACK_SZ];
static char gKeyServerUdpStack[KS_STACK_SZ];
static char gKeyClientStack[KS_STACK_SZ];
static char gWolfCastClientStack[KS_STACK_SZ];
static unsigned char gKeyServerMemory[KS_MEMORY_POOL_SZ];

/* Mutex for controlling the current key state. The Key
 * Client thread will be writing to the key state and
 * the wolfCast client will be reading it. Also, the
 * wolfCast client will set a semaphore to for the Key
 * Client to request a new key. */
static TX_MUTEX gKeyStateMutex;
static UINT gKeySet = 0;
static UINT gGetNewKey = 1;
static KeyRespPacket_t gKeyState;

static struct in_addr keySrvAddr = { IP_ADDRESS(192,168,2,1) };

extern NX_IP* nxIp;


static int isNetworkReady(ULONG timeout)
{
    UINT status;
    UINT ipStatus = 0;
    int isReady = 0;

    if (nxIp != NULL) {
        status = nx_ip_status_check(nxIp,
                                    NX_IP_RARP_COMPLETE, &ipStatus,
                                    timeout);
        if (status == NX_SUCCESS && ipStatus == NX_IP_RARP_COMPLETE)
            isReady = 1;
    }

    return isReady;
}


/* KeyServerEntry
 * Thread entry point to drive the key server. Key server really
 * shouldn't ever return, but the return code is checked and
 * reported, just in case. */
static void
KeyServerEntry(ULONG ignore)
{
    int result;
    WOLFSSL_HEAP_HINT *heap;

    (void)ignore;

    result = wolfSSL_Init();
    if (result != SSL_SUCCESS) {
        KS_PRINTF("KeyServer couldn't initialize wolfSSL. (%d)\n", result);
    }

    if (result == SSL_SUCCESS) {
        result = wc_LoadStaticMemory(&heap,
                                     gKeyServerMemory, sizeof(gKeyServerMemory),
                                     WOLFMEM_GENERAL, 1);
        if (result != 0) {
            KS_PRINTF("KeyServer couldn't get memory pool. (%d)\n", result);
        }
    }

    if (result == 0) {
        result = KeyServer_Init(heap);
        if (result != 0) {
            KS_PRINTF("KeyServer couldn't initialize. (%d)\n", result);
        }
    }

    if (result == 0) {
        result = KeyServer_Run(heap);
        if (result != 0) {
            KS_PRINTF("KeyServer terminated. (%d)\n", result);
        }
    }

    KeyServer_Free(heap);

    wolfSSL_Cleanup();
}


/* KeyServerUdpEntry
 * Thread entry point to drive the key server's UDP beacon. Key server
 * really shouldn't ever return, but the return code is checked and
 * reported, just in case. */
static void
KeyServerUdpEntry(ULONG ignore)
{
    int result;

    (void)ignore;

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
        KS_PRINTF("Key Service udp server waiting for network.\n");
    }

    result = KeyServer_RunUdp(NULL);
    if (result != 0) {
        KS_PRINTF("KeyServerUdp terminated. (%d)\n", result);
    }
}


/* KeyClientEntry
 * Thread entry point to drive the key client. */
static void
KeyClientEntry(ULONG ignore)
{
    int result;
    UINT status = TX_SUCCESS;
    KeyRespPacket_t keyResp;

    (void)ignore;

    result = wolfSSL_Init();
    if (result != SSL_SUCCESS) {
        KS_PRINTF("KeyClient couldn't initialize wolfSSL. (%d)\n", result);
        return;
    }

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
        KS_PRINTF("Key Service client waiting for network.\n");
    }

    while (1) {
        tx_thread_sleep(KS_TIMEOUT_KEY_CLIENT);

        if (status == TX_SUCCESS && gGetNewKey) {
            result = KeyClient_GetKey(&keySrvAddr, &keyResp, NULL);
            if (result != 0) {
                KS_PRINTF("Key retrieval failed\n");
                continue;
            }

            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_WRITE);
            if (status != TX_SUCCESS) {
                KS_PRINTF("Key client couldn't get state mutex\n");
            }
            memcpy(&gKeyState, &keyResp, sizeof(KeyRespPacket_t));
            gKeySet = 1;
            gGetNewKey = 0;
            status = tx_mutex_put(&gKeyStateMutex);
            if (status != TX_SUCCESS) {
                KS_PRINTF("Key client couldn't put state mutex\n");
            }
        }
    }
}


static int
sequenceCb(
        unsigned short peerId,
        unsigned int maxSeq,
        unsigned int curSeq,
        void* ctx)
{
    UINT status;

    (void)peerId;
    (void)maxSeq;
    (void)curSeq;
    (void)ctx;

    status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_READ);
    if (status != TX_SUCCESS) {
        KS_PRINTF("wolfCast callback couldn't get state mutex\n");
    }
    else {
        gGetNewKey = 1;

        status = tx_mutex_put(&gKeyStateMutex);
        if (status != TX_SUCCESS) {
            KS_PRINTF("wolfCast callback couldn't put state mutex\n");
        }
    }

    return status != TX_SUCCESS;
}


/* WolfCastClientEntry
 * Thread entry point to drive the wolfCast client. This wraps
 * the old chunk of code from test.c that was executed in the
 * the test_1hz() thread. The old globals used by the code are
 * now local variables. It will wait for the flag for the key
 * getting set to go true before starting to broadcast. */
static void
WolfCastClientEntry(ULONG ignore)
{
    SocketInfo_t socketInfo; /* Used in the WOLFSSL object. */
    WOLFSSL_CTX *ctx; /* Used in the WOLFSSL object. */
    WOLFSSL *curSsl = NULL;
    WOLFSSL *prevSsl = NULL;
    unsigned short epoch = 0;
    unsigned int txTime;
    unsigned int txCount;
    int error;
    int result;
    UINT status;
    KeyRespPacket_t keyState;
    int keySet = 0;
    const unsigned short peerIdList[] =
                            { SERVER_ID, OTHER_CLIENT_ID, FOREIGN_CLIENT_ID };

    (void)ignore;

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
        KS_PRINTF("wolfCast thread waiting for network.\n");
    }

    error = WolfcastInit(1, CLIENT_ID, &ctx, &socketInfo);
    if (!error) {
        error = WolfcastClientInit(&txTime, &txCount);
    }

    if (!error) {
        result = wolfSSL_CTX_mcast_set_highwater_cb(ctx, 5, 0, 0, sequenceCb);
        if (result != SSL_SUCCESS) {
            error = 1;
            KS_PRINTF("set mcast highwater cb error\n");
        }
    }

    if (!error) {
        keySet = 0;
        while (!keySet) {
            KS_PRINTF("wolfCast thread waiting for first key.\n");

            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_READ);
            if (status == TX_SUCCESS) {
                keySet = gKeySet;
                tx_mutex_put(&gKeyStateMutex);
            }

            tx_thread_sleep(KS_TIMEOUT_WOLFCAST_KEY_POLL);
        }
        keySet = 0;
    }

    while (1) {
        if (!error) {
            WOLFSSL *newSsl = NULL;
            unsigned short newEpoch;

            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_READ);
            if (status == TX_SUCCESS) {
                if (gKeySet) {
                    keySet = 1;
                    gKeySet = 0;
                    memcpy(&keyState, &gKeyState, sizeof(keyState));
                }
                status = tx_mutex_put(&gKeyStateMutex);
            }

            if (status == TX_SUCCESS) {
                error = WolfcastSessionNew(&newSsl, ctx, &socketInfo, 1,
                        peerIdList, sizeof(peerIdList) / sizeof(peerIdList[0]));
            }

            if (!error && newSsl != NULL && keySet) {
                keySet = 0;
                newEpoch = (keyState.epoch[0] << 8) | keyState.epoch[1];
                result = wolfSSL_set_secret(newSsl, newEpoch,
                                keyState.pms, sizeof(keyState.pms),
                                keyState.clientRandom, keyState.serverRandom,
                                keyState.suite);
                if (result != SSL_SUCCESS) {
                    error = 1;
                    KS_PRINTF("Couldn't set the session secret\n");
                }

                memset(&keyState, 0, sizeof(keyState));

                if (!error) {
                    if (prevSsl != NULL)
                        wolfSSL_free(prevSsl);
                    prevSsl = curSsl;
                    curSsl = newSsl;
                    epoch = newEpoch;
                }
            }
        }

        if (!error)
            error = WolfcastClient(&socketInfo, curSsl, prevSsl, epoch,
                                   CLIENT_ID, &txTime, &txCount);

        tx_thread_sleep(KS_TIMEOUT_WOLFCAST);
    }
}


/* WolfLocalInit
 * Runs the wolfCrypt test and benchmark. Sets up the mutex for the
 * group key access. Creates threads for the Key Server, Key Client,
 * and the wolfCast demo application. */
void
WolfLocalInit(void)
{
    UINT status;

    wolfcrypt_test(NULL);
    benchmark_test(NULL);

    if (KeySocket_Init() != 0) {
        KS_PRINTF("couldn't initialize the KeySocket\n");
        return;
    }

    status = tx_thread_create(&gKeyServerUdpThread, "key service udp server",
                              KeyServerUdpEntry, 0,
                              gKeyServerUdpStack, sizeof(gKeyServerUdpStack),
                              KS_PRIORITY, KS_THRESHOLD,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        KS_PRINTF("key %s thread create failed = 0x%02X\n",
                  "server udp", status);
        return;
    }

    status = tx_thread_create(&gKeyServerThread, "key service server",
                           KeyServerEntry, 0,
                           gKeyServerStack, sizeof(gKeyServerStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        KS_PRINTF("key %s thread create failed = 0x%02X\n", "server", status);
        return;
    }

    status = tx_mutex_create(&gKeyStateMutex, "key state mutex",
                             TX_NO_INHERIT);
    if (status != TX_SUCCESS) {
        KS_PRINTF("key state mutex create failed = 0x%02X\n", status);
        return;
    }

    status = tx_thread_create(&gKeyClientThread, "key service client",
                           KeyClientEntry, 0,
                           gKeyClientStack, sizeof(gKeyClientStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        KS_PRINTF("key %s thread create failed = 0x%02X\n", "client", status);
        return;
    }

    status = tx_thread_create(&gWolfCastClientThread, "wolfCast client",
                           WolfCastClientEntry, 0,
                           gWolfCastClientStack, sizeof(gWolfCastClientStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        KS_PRINTF("wolfCast client thread create failed = 0x%02X\n", status);
        return;
    }

    return;
}
