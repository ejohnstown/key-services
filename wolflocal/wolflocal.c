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

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#ifndef KEY_SERVICE_LOGGING_LEVEL
    #define KEY_SERVICE_LOGGING_LEVEL 0
#endif
#ifndef WOLFCAST_LOGGING_LEVEL
    #define WOLFCAST_LOGGING_LEVEL 0
#endif
#ifndef WOLFLOCAL_LOGGING_LEVEL
    #define WOLFLOCAL_LOGGING_LEVEL 0
#endif

#if KEY_SERVICE_LOGGING_LEVEL >= 1 || \
    WOLFCAST_LOGGING_LEVEL >= 1 || WOLFLOCAL_LOGGING_LEVEL >= 1
    #define KS_PRINTF bsp_debug_printf
#endif

#define KS_MEMORY_POOL_SZ 4096
#define KS_STACK_SZ 4096
#define KS_PRIORITY 15
#define KS_THRESHOLD 15

#define KS_TIMEOUT_1SEC 100
#define KS_TIMEOUT_NETWORK_READY KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_CLIENT KS_TIMEOUT_1SEC
#define KS_TIMEOUT_WOLFCAST_KEY_POLL KS_TIMEOUT_1SEC
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


/* Note: Return codes for wolfSSL code are of type int and typically
 * named "result". Return codes for ThreadX/NetX are of type UINT
 * and typically named "status". */

static TX_THREAD gKeyBcastUdpThread;
static TX_THREAD gKeyClientThread;
static TX_THREAD gWolfCastClientThread;

static char gKeyBcastUdpStack[KS_STACK_SZ];
static char gKeyClientStack[KS_STACK_SZ];
static char gWolfCastClientStack[KS_STACK_SZ];
static unsigned char gKeyServiceMemory[KS_MEMORY_POOL_SZ];

#ifdef WOLFLOCAL_TEST_KEY_SERVER
    static TX_THREAD gKeyServerThread;
    static char gKeyServerStack[KS_STACK_SZ];
#endif

/* Mutex for controlling the current key state. The Key
 * Client thread will be writing to the key state and
 * the wolfCast client will be reading it. Also, the
 * wolfCast client will set a semaphore to for the Key
 * Client to request a new key. */
static TX_MUTEX gKeyStateMutex;
static UINT gKeySet = 0;
UINT gGetNewKey = 1;
UINT gRequestRekey = 0;
static UINT gFindMaster = 1;
UINT gSwitchKeys = 1;
static KeyRespPacket_t gKeyState;
static WOLFSSL_HEAP_HINT *gHeapHint = NULL;
static struct in_addr gKeySrvAddr = { 0 };

extern NX_IP* nxIp;
extern unsigned short gKeyServerEpoch;


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


#ifdef WOLFLOCAL_TEST_KEY_SERVER

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
#if KEY_SERVICE_LOGGING_LEVEL >= 1
        KS_PRINTF("KeyServer couldn't initialize wolfSSL.\n");
#endif
    }

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
#if KEY_SERVICE_LOGGING_LEVEL >= 3
        KS_PRINTF("Key server waiting for network.\n");
#endif
    }

    while (gHeapHint == NULL) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
        KS_PRINTF("KeyServer waiting for heap.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_HEAP_INIT);
    }

    result = KeyServer_Init(gHeapHint);
    if (result != 0) {
#if KEY_SERVICE_LOGGING_LEVEL >= 1
        KS_PRINTF("KeyServer couldn't initialize. (%d)\n", result);
#endif
    }

    if (result == 0) {
        result = KeyServer_Run(gHeapHint);
        if (result != 0) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
            KS_PRINTF("KeyServer terminated. (%d)\n", result);
#endif
        }
    }

    KeyServer_Free(gHeapHint);
    wolfSSL_Cleanup();
}

#endif


static void
broadcastCb(CmdPacket_t* pkt)
{
    unsigned char* msg;

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
                gSwitchKeys = (msg[0] << 8) | msg[1];
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

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
#if KEY_SERVICE_LOGGING_LEVEL >= 3
        KS_PRINTF("Key Service bcast udp server waiting for network.\n");
#endif
    }

    while (gHeapHint == NULL) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
        KS_PRINTF("KeyBcast waiting for heap.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_HEAP_INIT);
    }

    result = KeyBcast_RunUdp(&gKeySrvAddr, broadcastCb, gHeapHint);
    if (result != 0) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
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
#if KEY_SERVICE_LOGGING_LEVEL >= 1
        KS_PRINTF("KeyClient couldn't initialize wolfSSL. (%d)\n", result);
#endif
        return;
    }

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
        KS_PRINTF("Key Service client waiting for network.\n");
#endif
    }

    while (gHeapHint == NULL) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
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
#if KEY_SERVICE_LOGGING_LEVEL >= 2
                KS_PRINTF("Couldn't get key state mutex to read\n");
#endif
            }
        }

        if (findMaster) {
            result = KeyClient_FindMaster(&gKeySrvAddr, gHeapHint);
            if (result != 0) {
#if KEY_SERVICE_LOGGING_LEVEL >= 3
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
#if WOLFCAST_LOGGING_LEVEL >= 1
                KS_PRINTF("Failed to request new key.\n");
#endif
            }
            else {
                requestRekey = 0;
#if WOLFCAST_LOGGING_LEVEL >= 1
                KS_PRINTF("New epoch will be %u.\n",
                          ((epochResp.epoch[0] << 8) | epochResp.epoch[1]));
#endif
            }
        }

        if (!findMaster && getNewKey && !storeKey) {
#if KEY_SERVICE_LOGGING_LEVEL >= 3
            KS_PRINTF("Key client getting key.\n");
#endif
            result = KeyClient_GetKey(&gKeySrvAddr, &keyResp, gHeapHint);
            if (result != 0) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
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
#if KEY_SERVICE_LOGGING_LEVEL >= 3
                KS_PRINTF("Key client got key\n");
#endif
                memcpy(&gKeyState, &keyResp, sizeof(KeyRespPacket_t));
                gKeySet = 1;
                storeKey = 0;
                tx_mutex_put(&gKeyStateMutex);
            }
            else {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
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
WolfCastClientEntry(ULONG ignore)
{
    SocketInfo_t socketInfo; /* Used in the WOLFSSL object. */
    WOLFSSL_CTX *ctx = NULL; /* Used in the WOLFSSL object. */
    WOLFSSL *curSsl = NULL;
    WOLFSSL *prevSsl = NULL;
    unsigned short epoch = 0;
    unsigned short newEpoch;
    unsigned int txTime;
    unsigned int txCount;
    int error;
    int result;
    UINT status;
    KeyRespPacket_t keyState;
    UINT keySet = 0;
    UINT switchKeys = 0;
    const unsigned short peerIdList[] =
                            { SERVER_ID, OTHER_CLIENT_ID, FOREIGN_CLIENT_ID };

    (void)ignore;

    while (!isNetworkReady(KS_TIMEOUT_NETWORK_READY)) {
#if WOLFCAST_LOGGING_LEVEL >= 3
        KS_PRINTF("wolfCast thread waiting for network.\n");
#endif
    }

    while (gHeapHint == NULL) {
#if KEY_SERVICE_LOGGING_LEVEL >= 2
        KS_PRINTF("WolfCast waiting for heap.\n");
#endif
        tx_thread_sleep(KS_TIMEOUT_HEAP_INIT);
    }

    error = WolfcastInit(1, CLIENT_ID, &ctx, &socketInfo);
    if (!error) {
        error = WolfcastClientInit(&txTime, &txCount);
    }

    if (!error) {
        keySet = 0;
        while (!keySet) {
#if WOLFCAST_LOGGING_LEVEL >= 3
            KS_PRINTF("wolfCast thread waiting for first key.\n");
#endif
            tx_thread_sleep(KS_TIMEOUT_WOLFCAST_KEY_POLL);

            status = tx_mutex_get(&gKeyStateMutex, TX_WAIT_FOREVER);
            if (status == TX_SUCCESS) {
#if WOLFCAST_LOGGING_LEVEL >= 3
                KS_PRINTF("wolfCast getting key set flag\n");
#endif
                keySet = gKeySet;
                status = tx_mutex_put(&gKeyStateMutex);
            }
            else {
#if WOLFCAST_LOGGING_LEVEL >= 3
                KS_PRINTF("Couldn't get key mutex. Trying again.\n");
#endif
            }
        }
        gSwitchKeys = (gKeyState.epoch[0] << 8) | gKeyState.epoch[1];
        keySet = 0;
    }

    while (1) {
        if (!error) {
            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_READ);
            if (status == TX_SUCCESS) {
                keySet = gKeySet;
                gKeySet = 0;
                switchKeys = gSwitchKeys;
                gSwitchKeys = 0;

                if (keySet) {
                    memcpy(&keyState, &gKeyState, sizeof(keyState));
                }
                status = tx_mutex_put(&gKeyStateMutex);
            }

            if (status == TX_SUCCESS && keySet) {
                keySet = 0;
                newEpoch = (keyState.epoch[0] << 8) | keyState.epoch[1];

#if WOLFCAST_LOGGING_LEVEL >= 1
                if (error) {
                    KS_PRINTF("Couldn't create new session\n");
                }
#endif
            }

            if (switchKeys) {
                if (switchKeys == newEpoch) {
                    WOLFSSL *newSsl = NULL;

                    if (!error) {
                        switchKeys = 0;
                        error = WolfcastSessionNew(&newSsl, ctx,
                                      &socketInfo, 1,
                                      peerIdList,
                                      sizeof(peerIdList) / sizeof(peerIdList[0]));
                    }
                    if (!error) {
                        result = wolfSSL_set_secret(newSsl, newEpoch,
                                    keyState.pms, sizeof(keyState.pms),
                                    keyState.clientRandom, keyState.serverRandom,
                                    keyState.suite);
                        if (result != SSL_SUCCESS) {
                            wolfSSL_free(newSsl);
                            error = 1;
#if WOLFCAST_LOGGING_LEVEL >= 1
                            KS_PRINTF("Couldn't set the session secret\n");
#endif
                        }

                        memset(&keyState, 0, sizeof(keyState));
                    }


                    if (!error) {
                        if (prevSsl != NULL) {
#if WOLFCAST_LOGGING_LEVEL >= 3
                            KS_PRINTF("Releasing old session.\n");
#endif
                            wolfSSL_free(prevSsl);
                        }
                        prevSsl = curSsl;
                        curSsl = newSsl;
                        epoch = newEpoch;
                        newSsl = NULL;
                    }
                }
                else {
#if WOLFCAST_LOGGING_LEVEL >= 2
                    KS_PRINTF("Missed a key change.\n");
#endif
                    gGetNewKey = 1;
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
#if KEY_SERVICE_LOGGING_LEVEL >= 1
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

#ifdef WOLFLOCAL_TEST_KEY_SERVER
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
#endif

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

    status = tx_thread_create(&gWolfCastClientThread, "wolfCast client",
                           WolfCastClientEntry, 0,
                           gWolfCastClientStack, sizeof(gWolfCastClientStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
#if WOLFLOCAL_LOGGING_LEVEL >= 1
        KS_PRINTF("wolfCast client thread create failed = 0x%02X\n", status);
#endif
        return;
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

#ifdef WOLFLOCAL_TEST_KEY_SERVER

    /* Give it a 15 count before trying to do anything. */
    if (count > 15) {
#if WOLFCAST_LOGGING_LEVEL >= 3
        KS_PRINTF("timer: %u\n", count);
#endif
        /* Every 10 seconds on the 10, generate new key. */
        if ((count % 10) == 0) {
#if WOLFCAST_LOGGING_LEVEL >= 3
            KS_PRINTF("timer: 10 on the 10\n");
#endif
            ret = KeyServer_GenNewKey(gHeapHint);
            if (ret) {
#if WOLFCAST_LOGGING_LEVEL >= 1
                KS_PRINTF("Failed to announce new key.\n");
#endif
            }
            else {
                status = tx_mutex_get(&gKeyStateMutex,
                                      KS_TIMEOUT_KEY_STATE_WRITE);
                if (status == TX_SUCCESS) {
                    gGetNewKey = 1;
                    tx_mutex_put(&gKeyStateMutex);
                }
            }
        }

        /* Every 10 seconds on the 2, announce new key change. */
        if ((count % 10) == 2) {
#if WOLFCAST_LOGGING_LEVEL >= 3
            KS_PRINTF("timer: 10 on the 2\n");
#endif
            if (KeyServer_IsRunning()) {
                ret = KeyServer_NewKeyUse(gHeapHint);
                if (ret) {
#if WOLFCAST_LOGGING_LEVEL >= 1
                    KS_PRINTF("Failed to announce key switch.\n");
#endif
                }
                else {
                    status = tx_mutex_get(&gKeyStateMutex,
                                          KS_TIMEOUT_KEY_STATE_WRITE);
                    if (status == TX_SUCCESS) {
                        gSwitchKeys = gKeyServerEpoch;
                        /* Should be an epoch number */
                        tx_mutex_put(&gKeyStateMutex);
                    }
                }
            }
        }
    }

#endif /* WOLFLOCAL_TEST_KEY_SERVER */

#ifdef WOLFLOCAL_TEST_KEY_REQUEST

    /* Give it a 15 count before trying to do anything. */
    if (count > 15) {
#if WOLFCAST_LOGGING_LEVEL >= 3
        KS_PRINTF("timer: %u\n", count);
#endif
        /* Every 10 seconds on the 10, request new key. */
        if ((count % 10) == 0) {
#if WOLFCAST_LOGGING_LEVEL >= 3
            KS_PRINTF("timer: 10 on the 10\n");
#endif
            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_WRITE);
            if (status == NX_SUCCESS) {
                gRequestRekey = 1;
                tx_mutex_put(&gKeyStateMutex);
            }
        }
    }

#endif /* WOLFLOCAL_TEST_KEY_REQUEST */

}
