#include "types.h"
#include "wolflocal.h"
#include "key-client.h"
#include "key-server.h"
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

#include <stdarg.h>

/* Filter the logging with bsp_debug_printf based on the provided
 * level value and the WOLFLOCAL_LOGGING_LEVEL constant. */
static void FilteredLog(int level, const char* fmt, ...)
{
    va_list args;
    char output[100];

    va_start(args, fmt);
    vsnprintf(output, sizeof(output), fmt, args);
    va_end(args);

    if (level <= WOLFLOCAL_LOGGING_LEVEL)
        bsp_debug_printf("%s", output);
}

#if WOLFLOCAL_LOGGING_LEVEL > 0
    #define WOLFLOCAL_LOG(...) do { if (1) FilteredLog(__VA_ARGS__); } while (0)
#else
    #define WOLFLOCAL_LOG(...) do { if (0) FilteredLog(__VA_ARGS__); } while (0)
#endif

#define KS_MEMORY_POOL_SZ 4096
#define KS_STACK_SZ 4096
#define KS_PRIORITY 21
#define KS_THRESHOLD 21

#define KS_TIMEOUT_1SEC 100
#define KS_TIMEOUT_NETWORK_READY KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_CLIENT KS_TIMEOUT_1SEC
#define KS_TIMEOUT_WOLFLOCAL_KEY_POLL KS_TIMEOUT_1SEC
//#define KS_TIMEOUT_WOLFCAST KS_TIMEOUT_1SEC
#define KS_TIMEOUT_KEY_STATE_WRITE TX_WAIT_FOREVER
#define KS_TIMEOUT_KEY_STATE_READ TX_NO_WAIT

//#define SERVER_ID 5
//#define FOREIGN_CLIENT_ID 23

#ifndef WOLFLOCAL_KEY_SWITCH_TIME
    #define WOLFLOCAL_KEY_SWITCH_TIME 15
#endif
#ifndef WOLFLOCAL_KEY_CHANGE_PERIOD
    #define WOLFLOCAL_KEY_CHANGE_PERIOD 60
#endif
//#ifndef WOLFLOCAL_FIND_MASTER_PERIOD
//    #define WOLFLOCAL_FIND_MASTER_PERIOD 5
//#endif
#ifndef WOLFLOCAL_STATS_PERIOD
    #define WOLFLOCAL_STATS_PERIOD 60
#endif

/* Note: Return codes for wolfSSL code are of type int and typically
 * named "result". Return codes for ThreadX/NetX are of type UINT
 * and typically named "status". */

static TX_THREAD gKeyBcastUdpThread;
static TX_THREAD gKeyClientThread;
//static TX_THREAD gWolfCastClientThread[3];
static TX_THREAD gKeyServerThread;

static char gKeyBcastUdpStack[KS_STACK_SZ];
static char gKeyClientStack[KS_STACK_SZ];
//static char gWolfCastClientStack[3][KS_STACK_SZ];
static char gKeyServerStack[KS_STACK_SZ];
LINK_SECTION(bss_sdram) static unsigned char gKeyServiceMemory[KS_MEMORY_POOL_SZ];

#ifdef WOLFSSL_STATIC_MEMORY
    #if defined(NETX) && defined(__RX__)
        #define MEMORY_SECTION LINK_SECTION(bss_sdram)
    #else
        #define MEMORY_SECTION
    #endif
    MEMORY_SECTION unsigned char gWolfCastMemory[WOLFLOCAL_STATIC_MEMORY_SZ];
    LINK_SECTION(data_sdram) UCHAR *heap_address = gWolfCastMemory;
    LINK_SECTION(data_sdram) UINT	heap_size = WOLFLOCAL_STATIC_MEMORY_SZ;
#endif


/* Mutex for controlling the current key state. The Key
 * Client thread will be writing to the key state and
 * the wolfCast client will be reading it. Also, the
 * wolfCast client will set a semaphore to for the Key
 * Client to request a new key. */
static TX_MUTEX gKeyStateMutex;
static TX_EVENT_FLAGS_GROUP gEventFlags;
LINK_SECTION(bss_sdram)  UINT gKeySet = 0;
LINK_SECTION(data_sdram) UINT gGetNewKey = 1;
LINK_SECTION(bss_sdram)  UINT gRekeyNow = 0;
LINK_SECTION(bss_sdram) UINT gRequestRekey = 0;
LINK_SECTION(data_sdram) static UINT gFindMaster = 1;
LINK_SECTION(data_sdram) UINT gSwitchKeys = 1;
LINK_SECTION(bss_sdram) KeyRespPacket_t gKeyState;
LINK_SECTION(bss_sdram) static WOLFSSL_HEAP_HINT *gHeapHint = NULL;
LINK_SECTION(bss_sdram) struct in_addr gKeySrvAddr = { 0 };
LINK_SECTION(bss_sdram) UINT gRekeyPending = 0;
LINK_SECTION(bss_sdram) static UINT gSwitchKeyCount = 0;
LINK_SECTION(bss_sdram) static UINT gUseKeyCount = 0;
LINK_SECTION(bss_sdram) wolfWrapper_t *gWrapper;
LINK_SECTION(bss_sdram) ULONG gAddr = 0;
LINK_SECTION(bss_sdram) ULONG gMask = 0;

/* Group address for the wolfCast multicast group. */
const struct in_addr gGroupAddr = { .s_addr = 0xE2000003 };

/* Port number for the wolfCast multicast group. */
static const unsigned short gGroupPort = 12345;

/* Port number for the KeyBcast server all endpoints run. */
static const unsigned short gBcastPort = 22222;

/* Port number for the KeyServer all endpoints run. */
static const unsigned short gServPort = 11111;


//const USHORT gPeerIdList[] = { SERVER_ID, FOREIGN_CLIENT_ID };
//#define PEER_ID_LIST_SZ (sizeof(gPeerIdList)/sizeof(gPeerIdList[0]))


extern NX_IP* nxIp;
extern NX_PACKET_POOL* nxPool;
extern unsigned short gKeyServerEpoch;
extern unsigned char gPeerId;

#define KS_EVENT_HEAP (1 << 0)
#define KS_EVENT_ADDR (1 << 1)

void WolfLocalRekey(void)
{
	gRekeyNow = 1;
}

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


static void
keyServerCb(CmdPacket_t* pkt)
{
    if (pkt &&
        (pkt->header.type == CMD_PKT_TYPE_KEY_NEW ||
         (pkt->header.type == CMD_PKT_TYPE_KEY_REQ &&
          !gRekeyPending &&
          wolfSSL_mcast_peer_known(gWrapper->curSsl, pkt->header.id)))) {

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

    {
        ULONG flags;
        result = tx_event_flags_get(&gEventFlags, KS_EVENT_HEAP,
                                    TX_AND, &flags, TX_WAIT_FOREVER);
        if (result == TX_SUCCESS)
            WOLFLOCAL_LOG(3, "KeyServerEntry got the start event (%u)\n",
                          flags);
        else
            WOLFLOCAL_LOG(1, "KeyServerEntry failed to get event flags\n");
    }

    if (wolfSSL_Init() != SSL_SUCCESS) {
        WOLFLOCAL_LOG(1, "KeyServer couldn't initialize wolfSSL.\n");
    }

    while (!isAddrSet()) {
        WOLFLOCAL_LOG(3, "Key server waiting for network.\n");
        tx_thread_sleep(KS_TIMEOUT_NETWORK_READY);
    }

    {
        struct in_addr inaddr;
        inaddr.s_addr = gAddr;
        result = KeyServer_Init(gHeapHint, &inaddr);
    }

    if (result != 0) {
        WOLFLOCAL_LOG(1, "KeyServer couldn't initialize. (%d)\n", result);
    }

    tx_event_flags_set(&gEventFlags, KS_EVENT_ADDR, TX_OR);

    if (result == 0) {
        result = KeyServer_Run(keyServerCb, 99, gHeapHint);
        if (result != 0) {
            WOLFLOCAL_LOG(2, "KeyServer terminated. (%d)\n", result);
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
    	gKeySrvAddr.s_addr = gAddr;
    	WOLFLOCAL_LOG(3, "I am the key server, I should ignore my broadcasts.\n");
        return;
    }

    if (pkt != NULL) {
        switch (pkt->header.type) {
            case CMD_PKT_TYPE_KEY_CHG:
                /* trigger key change */
                msg = pkt->msg.keyChgResp.ipaddr;
                gGetNewKey = 1;
                break;
            case CMD_PKT_TYPE_KEY_USE:
                /* switch to new key */
                msg = pkt->msg.epochResp.epoch;
                epoch = (msg[0] << 8) | msg[1];
                if (epoch != gKeyServerEpoch) {
                    gSwitchKeys = epoch;
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
    ULONG flags = 0;
    int result;

    (void)ignore;

    result = tx_event_flags_get(&gEventFlags, (KS_EVENT_HEAP | KS_EVENT_ADDR),
                                TX_AND, &flags, TX_WAIT_FOREVER);
    if (result == TX_SUCCESS)
        WOLFLOCAL_LOG(3, "KeyBcastUdpEntry got the start event (%u)\n", flags);
    else
        WOLFLOCAL_LOG(1, "KeyBcastUdpEntry failed to get event flags\n");

    result = KeyBcast_RunUdp(&gGroupAddr, broadcastCb, gHeapHint);
    if (result != 0) {
        WOLFLOCAL_LOG(2, "KeyBcastUdp terminated. (%d)\n", result);
    }
}


/* KeyClientEntry
 * Thread entry point to drive the key client. It initializes wolfSSL for
 * its use, waits for the network interface to be ready, then it loops
 * trying to get key updates. */
static void
KeyClientEntry(ULONG ignore)
{
    ULONG flags = 0;
    int result;
    UINT findMaster = 0;
    UINT requestRekey = 0;
    UINT getNewKey = 0;
    UINT storeKey = 0;
    UINT status = TX_SUCCESS;
    KeyRespPacket_t keyResp;

    (void)ignore;

    result = tx_event_flags_get(&gEventFlags, (KS_EVENT_HEAP | KS_EVENT_ADDR),
                                TX_AND, &flags, TX_WAIT_FOREVER);
    if (result == TX_SUCCESS)
        WOLFLOCAL_LOG(3, "KeyClientEntry got the start event (%u)\n", flags);
    else
        WOLFLOCAL_LOG(1, "KeyClientEntry failed to get event flags\n");

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
                WOLFLOCAL_LOG(2, "Couldn't get key state mutex to read\n");
            }
        }

        if (findMaster) {
        	gKeySrvAddr = gGroupAddr;
            result = KeyClient_FindMaster(&gKeySrvAddr, gHeapHint);
            if (result != 0) {
                WOLFLOCAL_LOG(3, "Key server didn't announce itself.\n");
            }
            else
                findMaster = 0;
        }

        if (!findMaster && requestRekey && !storeKey) {
            EpochRespPacket_t epochResp;
            result = KeyClient_NewKeyRequest(&gKeySrvAddr, &epochResp, gHeapHint);
            if (result) {
                WOLFLOCAL_LOG(1, "Failed to request new key.\n");
            }
            else {
                requestRekey = 0;
                WOLFLOCAL_LOG(1, "New epoch will be %u.\n",
                          ((epochResp.epoch[0] << 8) | epochResp.epoch[1]));
            }
        }

        if (!findMaster && getNewKey && !storeKey) {
            WOLFLOCAL_LOG(3, "Key client getting key.\n");
            result = KeyClient_GetKey(&gKeySrvAddr, &keyResp, gHeapHint);
            if (result != 0) {
                WOLFLOCAL_LOG(2, "Unable to retrieve key\n");
            }
            else {
                getNewKey = 0;
                storeKey = 1;
            }
        }

        if (storeKey) {
            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_WRITE);
            if (status == TX_SUCCESS) {
                WOLFLOCAL_LOG(3, "Key client got key\n");
                memcpy(&gKeyState, &keyResp, sizeof(KeyRespPacket_t));
                KeyServer_SetKeyResp(&gKeyState, gHeapHint);
                gKeySet = 1;
                storeKey = 0;
                tx_mutex_put(&gKeyStateMutex);
            }
            else {
                WOLFLOCAL_LOG(2, "Couldn't get key state mutex to write\n");
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
//static void
//WolfCastClientEntry(ULONG streamId)
//{
//    wolfWrapper_t* wrapper;
//    unsigned int txTime;
//    unsigned int txCount;
//    int error;
//
//    {
//        ULONG flags = 0;
//        error = tx_event_flags_get(&gEventFlags, KS_EVENT_ADDR,
//                                   TX_AND, &flags, TX_WAIT_FOREVER);
//        if (error == TX_SUCCESS)
//            WOLFLOCAL_LOG(3, "WolfCastClientEntry got the start event (%u)\n",
//                          flags);
//        else
//            WOLFLOCAL_LOG(1, "WolfCastClientEntry failed to get event flags\n");
//    }
//
//    wrapper = &gWrappers[streamId];
//
//    error = wolfWrapper_Init(wrapper, streamId, gPeerId,
//                             gGroupPort + streamId, gGroupAddr.s_addr,
//                             gPeerIdList, PEER_ID_LIST_SZ,
//                             gWolfCastMemory[streamId],
//                             sizeof(gWolfCastMemory[streamId]));
//
//    if (!error)
//        error = WolfcastClientInit(&txTime, &txCount);
//
//    while (!error) {
//        error = wolfWrapper_Update(wrapper);
//        if (!error)
//            error = WolfcastClient(wrapper, &txTime, &txCount);
//        if (!error)
//            tx_thread_sleep(KS_TIMEOUT_WOLFCAST);
//    }
//
//    WOLFLOCAL_LOG(3, "wolfCast thread %u ended.\n", streamId);
//}


#ifdef DEBUG_WOLFSSL
/* WolfLocalLog
 * Logging callback function that is passed to wolfSSL if debugging is
 * enabled in the build. */
static void WolfLocalLog(const int logLevel, const char *const logMessage)
{
    (void)logLevel;
    WOLFLOCAL_LOG(1, "%s\n", logMessage);
}
#endif


/* WolfLocalInit
 * Runs the wolfCrypt test and benchmark. Sets up the mutex for the
 * group key access. Creates threads for the Key Server, Key Client,
 * and the wolfCast demo application. */
void
WolfLocalInit(wolfWrapper_t *wrapper, UCHAR id)
{
    UINT status;
    //int i;

    status = tx_event_flags_create(&gEventFlags, "WolfLocal Event Flags");
    if (status != TX_SUCCESS)
        WOLFLOCAL_LOG(1, "couldn't create event flags");

    gWrapper = wrapper;
    gPeerId = id;

#ifdef DEBUG_WOLFSSL
    wolfSSL_SetLoggingCb(WolfLocalLog);
#endif

    if (KeySocket_Init() != 0) {
        WOLFLOCAL_LOG(1, "couldn't initialize the KeySocket\n");
        return;
    }
    KeyServices_Init(id, gBcastPort, gServPort);

    status = tx_mutex_create(&gKeyStateMutex, "key state mutex",
                             TX_NO_INHERIT);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key state mutex create failed = 0x%02X\n", status);
        return;
    }

    status = wc_LoadStaticMemory(&gHeapHint,
                                 gKeyServiceMemory, sizeof(gKeyServiceMemory),
                                 WOLFMEM_GENERAL, 1);
    if (status != 0) {
        WOLFLOCAL_LOG(1, "WolfLocalInit couldn't get memory pool. (%d)\n", status);
    }
    status = tx_event_flags_set(&gEventFlags, KS_EVENT_HEAP, TX_OR);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "couldn't set the heap ready flag\n");
        return;
    }

    status = tx_thread_create(&gKeyBcastUdpThread,
                              "key service bcast udp server",
                              KeyBcastUdpEntry, 0,
                              gKeyBcastUdpStack, sizeof(gKeyBcastUdpStack),
                              KS_PRIORITY, KS_THRESHOLD,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key server bcast udp thread create failed = 0x%02X\n",
                  status);
        return;
    }

    status = tx_thread_create(&gKeyServerThread, "key service server",
                           KeyServerEntry, 0,
                           gKeyServerStack, sizeof(gKeyServerStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key server thread create failed = 0x%02X\n", status);
        return;
    }

    status = tx_thread_create(&gKeyClientThread, "key service client",
                           KeyClientEntry, 0,
                           gKeyClientStack, sizeof(gKeyClientStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key client thread create failed = 0x%02X\n", status);
        return;
    }

//    for (i = 0; i < 3; i++)
//    {
//        status = tx_thread_create(&gWolfCastClientThread[i], "wolfCast client",
//                               WolfCastClientEntry, i,
//                               gWolfCastClientStack[i],
//                               sizeof(gWolfCastClientStack[i]),
//                               KS_PRIORITY, KS_THRESHOLD,
//                               TX_NO_TIME_SLICE, TX_AUTO_START);
//        if (status != TX_SUCCESS) {
//            WOLFLOCAL_LOG(1,
//                          "wolfCast client thread %u create failed = 0x%02X\n",
//                          i, status);
//            return;
//        }
//    }

    return;
}


void WolfLocalTimer(void)
{
    static unsigned int count = 0;
    UINT status;
    int ret;

    if (count == 0) {
        ULONG flags = 0;
        status = tx_event_flags_get(&gEventFlags,
                                    (KS_EVENT_HEAP | KS_EVENT_ADDR),
                                    TX_AND, &flags, TX_NO_WAIT);
        if (status != TX_SUCCESS) {
            WOLFLOCAL_LOG(3, "timer: event flags not set yet\n");
            return;
        }

        if (flags != (KS_EVENT_HEAP | KS_EVENT_ADDR)) {
            WOLFLOCAL_LOG(3, "timer: flags not set correctly\n");
            return;
        }

        WOLFLOCAL_LOG(3, "timer: good to go!\n");
    }

    count++;

    if (!KeyServer_IsRunning())
    {
    	gRekeyPending = 0;
    }

    WOLFLOCAL_LOG(3, "timer: %u\n", count);
    /* Every X seconds on the 0, ... */
    if (((count % WOLFLOCAL_KEY_CHANGE_PERIOD) == 0  && !gSwitchKeyCount && !gUseKeyCount) || gRekeyNow) {
        WOLFLOCAL_LOG(3, "timer: %u on the 0\n", WOLFLOCAL_KEY_CHANGE_PERIOD);
        if (KeyServer_IsRunning()) {
        	gKeySrvAddr.s_addr = gAddr;
            if (!gRekeyPending) {
                ret = KeyServer_GenNewKey(gHeapHint);
                if (ret) {
                    WOLFLOCAL_LOG(1, "Failed to announce new key.\n");
                }
                else {
                    status = tx_mutex_get(&gKeyStateMutex,
                                          KS_TIMEOUT_KEY_STATE_WRITE);
                    if (status == TX_SUCCESS) {
                    	gRekeyNow = 0;
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
            status = tx_mutex_get(&gKeyStateMutex, KS_TIMEOUT_KEY_STATE_WRITE);
            if (status == NX_SUCCESS) {
                gRequestRekey = 1;
                tx_mutex_put(&gKeyStateMutex);
            }
#endif /* WOLFLOCAL_TEST_KEY_REQUEST */
        }
    }

    if (gSwitchKeyCount && gUseKeyCount)
        gUseKeyCount = 0;

    /* If the switch key count is set, decrement it. If it becomes 0,
     * switch the keys. */
    if (gSwitchKeyCount) {
        gSwitchKeyCount--;
        if (gSwitchKeyCount != 0) {
            WOLFLOCAL_LOG(3, "timer: reannouncing the new key\n");
            KeyServer_NewKeyChange(gHeapHint);
        }
        else {
            WOLFLOCAL_LOG(3, "timer: 15 seconds later\n");
            if (KeyServer_IsRunning()) {
            	gKeySrvAddr.s_addr = gAddr;
                gUseKeyCount = WOLFLOCAL_KEY_SWITCH_TIME;
                ret = KeyServer_NewKeyUse(gHeapHint);
                if (ret) {
                    WOLFLOCAL_LOG(1, "Failed to announce key switch.\n");
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
                gRekeyPending = 0;
            }
        }
    }

    if (gUseKeyCount) {
        gUseKeyCount--;
        if (gUseKeyCount != 0) {
            ret = KeyServer_NewKeyUse(gHeapHint);
            if (ret) {
                WOLFLOCAL_LOG(1, "Failed to announce key switch.\n");
            }
        }
    }

    if ((count % WOLFLOCAL_STATS_PERIOD) == 0) {
        unsigned int ks, mac, replay, epoch;
//        unsigned int i;

        ks = KeyServer_GetAuthFailCount();
        WOLFLOCAL_LOG(3, "Key Server auth fail counts: %u\n", ks);

		wolfWrapper_GetErrorStats(gWrapper, &mac, &replay, &epoch);
		WOLFLOCAL_LOG(3, "Wrapper macFail: %u\n"
				  	     "    replayCount: %u\n"
				  	  	 "      epochDrop: %u\n",
				  	  	 mac, replay, epoch);
//        for (i = 0; i < 3; i++) {
//            wolfWrapper_GetErrorStats(&gWrappers[i], &mac, &replay, &epoch);
//            WOLFLOCAL_LOG(3, "Wrapper[%u] macFail: %u\n"
//                      "            replayCount: %u\n"
//                      "            epochDrop: %u\n",
//                      i, mac, replay, epoch);
//        }
    }

#if 0
    if ((count % WOLFLOCAL_FIND_MASTER_PERIOD) == 3) {
        WOLFLOCAL_LOG(3, "timer: %u on the 3\n",
                      WOLFLOCAL_FIND_MASTER_PERIOD);
        if (!KeyServer_IsRunning()) {
            struct in_addr scratch;
            WOLFLOCAL_LOG(3, "finding the master\n");
            ret = KeyClient_FindMaster(&scratch, gHeapHint);
            if (ret != 0) {
                WOLFLOCAL_LOG(2,
                              "Key server didn't announce itself, "
                              "becoming master.\n");
                KeyServer_Resume();
            }
        }
    }
#endif
}


struct in_addr WolfLocalGetKeySrvAddr(void)
{
	return gKeySrvAddr;
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
        WOLFLOCAL_LOG(1, "transmit callback invalid parameters\n");
        goto exit;
    }
    wrapper = (wolfWrapper_t*)ctx;

    status = nx_packet_allocate(wrapper->pool, &pkt,
                                NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "couldn't allocate packet wrapper\n");
        goto exit;
    }

    status = nx_packet_data_append(pkt, buf, sz,
                                   wrapper->pool, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "couldn't append data to packet\n");
        goto exit;
    }

    status = nx_udp_socket_send(&wrapper->realTxSocket, pkt,
                                wrapper->groupAddr, wrapper->groupPort);
    if (status != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "tx error\n");
        goto exit;
    }

exit:
    if (status != NX_SUCCESS) {
        sz = WOLFSSL_CBIO_ERR_GENERAL;

        /* In case of error, release packet. */
        status = nx_packet_release(pkt);
        if (status != NX_SUCCESS) {
            WOLFLOCAL_LOG(1, "couldn't release packet\n");
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
        WOLFLOCAL_LOG(1, "receive callback invalid parameters\n");
        goto exit;
    }

    wrapper = (wolfWrapper_t*)ctx;
    pkt = wrapper->rxPacket;
    if (pkt == NULL) {
        WOLFLOCAL_LOG(1, "no packet\n");
        status = NX_NO_PACKET;
        goto exit;
    }

    status = nx_packet_length_get(pkt, &rxSz);
    if (status != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "couldn't get packet length\n");
        goto exit;
    }

    if (rxSz > (unsigned long)sz) {
        WOLFLOCAL_LOG(1, "receive packet too large for buffer\n");
        goto exit;
    }

    status = nx_packet_data_retrieve(pkt, buf, &rxSz);
    if (status != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "couldn't retrieve packet\n");
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
            WOLFLOCAL_LOG(1, "couldn't release packet\n");
        }
        else
            wrapper->rxPacket = NULL;
    }

    return sz;
}



int wolfWrapper_Init(wolfWrapper_t* wrapper,
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

    wrapper->myId = myId;
    wrapper->groupAddr = groupAddr;
    wrapper->groupPort = groupPort;
    wrapper->peerIdList = peerIdList;
    wrapper->peerIdListSz = peerIdListSz;
    wrapper->ip = nxIp;
    wrapper->pool = nxPool;

    ret = wolfSSL_CTX_load_static_memory(&wrapper->ctx,
                                         wolfDTLSv1_2_client_method_ex,
                                         heap, heapSz, 0, 2);
    if (ret != SSL_SUCCESS) {
        WOLFLOCAL_LOG(1, "unable to load static memory and create ctx\n");
        goto exit;
    }

    wolfSSL_SetIOSend(wrapper->ctx, NetxDtlsTxCallback);
    wolfSSL_SetIORecv(wrapper->ctx, NetxDtlsRxCallback);
    ret = wolfSSL_CTX_mcast_set_member_id(wrapper->ctx, myId);
    if (ret != SSL_SUCCESS) {
        WOLFLOCAL_LOG(1, "set mcast member id error\n");
        goto exit;
    }

    ret = nx_udp_enable(wrapper->ip);
    if (ret == NX_ALREADY_ENABLED) {
        WOLFLOCAL_LOG(3, "UDP already enabled\n");
    }
    else if (ret != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "cannot enable UDP\n");
        goto exit;
    }

    ret = nx_igmp_enable(wrapper->ip);
    if (ret == NX_ALREADY_ENABLED) {
        WOLFLOCAL_LOG(3, "IGMP already enabled\n");
    }
    else if (ret != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "cannot enable IGMP\n");
        goto exit;
    }

//    ret = nx_udp_socket_create(wrapper->ip, &wrapper->realTxSocket,
//                               "Multicast TX Socket",
//                               NX_IP_NORMAL, NX_DONT_FRAGMENT,
//                               NX_IP_TIME_TO_LIVE, 30);
//    if (ret != NX_SUCCESS) {
//        WOLFLOCAL_LOG(1, "unable to create tx socket\n");
//        goto exit;
//    }
//
//    ret = nx_udp_socket_bind(&wrapper->realTxSocket, NX_ANY_PORT, NX_NO_WAIT);
//    if (ret != NX_SUCCESS) {
//        WOLFLOCAL_LOG(1, "tx bind failed\n");
//        goto exit;
//    }

    ret = nx_igmp_loopback_disable(wrapper->ip);

    if (ret != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "couldn't disable multicast loopback\n");
        goto exit;
    }

//    ret = nx_udp_socket_create(wrapper->ip, &wrapper->realRxSocket,
//                               "Multicast RX Socket",
//                               NX_IP_NORMAL, NX_DONT_FRAGMENT,
//                               NX_IP_TIME_TO_LIVE, 30);
//    if (ret != NX_SUCCESS) {
//        WOLFLOCAL_LOG(1, "unable to create rx socket\n");
//        goto exit;
//    }
//
//    ret = nx_udp_socket_bind(&wrapper->realRxSocket,
//                             wrapper->groupPort, NX_NO_WAIT);
//    if (ret != NX_SUCCESS) {
//        WOLFLOCAL_LOG(1, "rx bind failed\n");
//        goto exit;
//    }
//
//    ret = nx_igmp_multicast_join(wrapper->ip, wrapper->groupAddr);
//    if (ret != NX_SUCCESS) {
//        WOLFLOCAL_LOG(1, "setsockopt mc add membership failed\n");
//        goto exit;
//    }

    /* Wait for the first key. */
    while (!keySet) {
        WOLFLOCAL_LOG(3, "wolfCast thread waiting for first key.\n");
        tx_thread_sleep(KS_TIMEOUT_WOLFLOCAL_KEY_POLL);

        ret = tx_mutex_get(&gKeyStateMutex, TX_WAIT_FOREVER);
        if (ret == TX_SUCCESS) {
            WOLFLOCAL_LOG(3, "wolfCast getting key set flag\n");
            keySet = gKeySet;
            ret = tx_mutex_put(&gKeyStateMutex);
        }
        else {
            WOLFLOCAL_LOG(3, "Couldn't get key mutex. Trying again.\n");
        }
    }
    gSwitchKeys = (gKeyState.epoch[0] << 8) | gKeyState.epoch[1];

exit:
    return ret;
}


static int wolfWrapper_NewSession(wolfWrapper_t* wrapper, WOLFSSL** ssl)
{
    int ret = SSL_SUCCESS;
    UINT i;
    WOLFSSL* newSsl = NULL;

    if (wrapper == NULL || ssl == NULL) {
        WOLFLOCAL_LOG(1, "wolfWrapper_NewWrapper invalid parameters\n");
        goto exit;
    }

    newSsl = wolfSSL_new(wrapper->ctx);
    if (newSsl == NULL) {
        WOLFLOCAL_LOG(1, "ssl new error\n");
        goto exit;
    }

    wolfSSL_SetIOWriteCtx(newSsl, wrapper);
    wolfSSL_SetIOReadCtx(newSsl, wrapper);
    wolfSSL_set_using_nonblock(newSsl, 1);

    for (i = 0; i < wrapper->peerIdListSz; i++) {
        ret = wolfSSL_mcast_peer_add(newSsl, wrapper->peerIdList[i], 0);
        if (ret != SSL_SUCCESS) {
            WOLFLOCAL_LOG(1, "mcast add peer error\n");
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

        wrapper->keySet = gKeySet;
        gKeySet = 0;
        wrapper->switchKeys = gSwitchKeys;
        gSwitchKeys = 0;

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
        WOLFLOCAL_LOG(3, "switchKeys = %u, newEpoch = %u, epoch = %u\n",
                  wrapper->switchKeys, wrapper->newEpoch, wrapper->epoch);
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
                            wrapper->keyState.clientRandom[0],
                            wrapper->keyState.serverRandom[0],
                            wrapper->keyState.suite);
            if (status != SSL_SUCCESS) {
                error = 1;
                wolfSSL_free(newSsl);
                WOLFLOCAL_LOG(1, "Couldn't set the session secret\n");
                goto exit;
            }
            memset(&wrapper->keyState, 0, sizeof(wrapper->keyState));

            if (wrapper->prevSsl != NULL) {
                unsigned int macCount = 0, replayCount = 0;
                WOLFLOCAL_LOG(3, "Releasing old session.\n");

                wolfSSL_dtls_get_drop_stats(wrapper->prevSsl,
                                            &macCount, &replayCount);
                wrapper->macDropCount += macCount;
                wrapper->replayDropCount += replayCount;
                wolfSSL_free(wrapper->prevSsl);
            }
            wrapper->prevSsl = wrapper->curSsl;
            wrapper->prevEpoch = wrapper->epoch;
            wrapper->curSsl = newSsl;
            wrapper->epoch = wrapper->newEpoch;
            newSsl = NULL;
        }
        else if (wrapper->switchKeys == wrapper->epoch) {
            /* Happens when a client rejoins, the master rekeys,
             * and sends out the rekey messages for the peers. */
            WOLFLOCAL_LOG(3, "Spurious key switch, ignoring.\n");
        }
        else {
            WOLFLOCAL_LOG(2, "Missed a key change.\n");
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
        WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
                  wolfSSL_ERR_reason_error_string(sentSz));
    }

exit:
    return sentSz;
}


void wolfWrapper_Read_Packet(wolfWrapper_t* wrapper, NX_PACKET *nxPacket, USHORT* peerId,
                   void* buf, int sz, int* recvSz)
{
    UINT nx_status;
    int status = 0;
    unsigned short epoch;

    if (wrapper != NULL && buf != NULL && sz != 0)
    {
        wrapper->rxPacket = nxPacket;
		epoch = GetEpoch(nxPacket);
		if (epoch == wrapper->epoch && wrapper->curSsl != NULL)
		{
			status = wolfSSL_mcast_read(wrapper->curSsl, peerId, buf, sz);
			if (status < 0)
			{
				status = wolfSSL_get_error(wrapper->curSsl, status);
				if (status == VERIFY_MAC_ERROR || status == DECRYPT_ERROR)
				{
					if (epoch == wrapper->prevEpoch && wrapper->prevSsl != NULL)
					{
						status = wolfSSL_mcast_read(wrapper->prevSsl, peerId, buf, sz);
						if (status < 0)
						{
							status = wolfSSL_get_error(wrapper->prevSsl, status);
							if (status == VERIFY_MAC_ERROR || status == DECRYPT_ERROR)
							{
								WOLFLOCAL_LOG(3, "Allowable DTLS error. Ignoring a message.\n");
							}
							else if (status != SSL_ERROR_WANT_READ)
							{
								WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
										  wolfSSL_ERR_reason_error_string(status));
							}
						    status = 0;
						}
					}
					else
					{
						WOLFLOCAL_LOG(3, "Allowable DTLS error. Ignoring a message.\n");
					}
				}
				else if (status != SSL_ERROR_WANT_READ)
				{
					WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
							  wolfSSL_ERR_reason_error_string(status));
				}
			    status = 0;
			}
		}
		else if (epoch == wrapper->prevEpoch && wrapper->prevSsl != NULL)
		{
			status = wolfSSL_mcast_read(wrapper->prevSsl, peerId, buf, sz);
			if (status < 0)
			{
				status = wolfSSL_get_error(wrapper->prevSsl, status);
				if (status == VERIFY_MAC_ERROR || status == DECRYPT_ERROR)
				{
					WOLFLOCAL_LOG(3, "Allowable DTLS error. Ignoring a message.\n");
				}
				else if (status != SSL_ERROR_WANT_READ)
				{
					WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
							  wolfSSL_ERR_reason_error_string(status));
				}
			    status = 0;
			}
		}
    }
	if (status > 0)
	{
		*recvSz = status;
	}
	else
	{
		if (epoch == wrapper->newEpoch)
		{
			/* We may have missed a new key update or a switch keys. */
			gSwitchKeys = epoch;
		}
		if (KeyServer_IsRunning())
		{
			gKeySrvAddr.s_addr = gAddr;
//			if (epoch > wrapper->epoch)
//			{
//				gKeyServerEpoch = epoch;
//			}
		}
		WOLFLOCAL_LOG(3, "Ignoring message unknown Epoch %hu Have %hu & %hu\n", epoch, wrapper->prevEpoch, wrapper->epoch);
		wrapper->epochDropCount++;
	}
    if (wrapper != NULL && wrapper->rxPacket != NULL)
    {
        nx_status = nx_packet_release(wrapper->rxPacket);
        if (nx_status != NX_SUCCESS)
        {
            WOLFLOCAL_LOG(1, "couldn't release packet\n");
        }
        wrapper->rxPacket = NULL;
    }
}

int wolfWrapper_Read(wolfWrapper_t* wrapper, USHORT* peerId,
                   void* buf, int sz)
{
    UINT status;
    NX_PACKET *nxPacket = NULL;
    int recvSz = 0;

    if (wrapper == NULL || buf == NULL || sz == 0)
        return recvSz;

    status = nx_udp_socket_receive(&wrapper->realRxSocket,
                                   &nxPacket, NX_NO_WAIT);
    if (status != NX_SUCCESS)
        return recvSz;

    wolfWrapper_Read_Packet(wrapper, nxPacket, peerId, buf, sz, &recvSz);

    return recvSz;
}


int wolfWrapper_GetErrorStats(wolfWrapper_t* wrapper,
                              unsigned int* macDropCount,
                              unsigned int* replayDropCount,
                              unsigned int* epochDropCount)
{
    unsigned int macCount = 0, replayCount = 0;
    unsigned int prevMacCount = 0, prevReplayCount = 0;
    int ret = 0;

    if (wrapper != NULL) {
        ret = wolfSSL_dtls_get_drop_stats(wrapper->curSsl,
                                          &macCount, &replayCount);
        if (ret == SSL_SUCCESS && wrapper->prevSsl != NULL)
            ret = wolfSSL_dtls_get_drop_stats(wrapper->prevSsl,
                                              &prevMacCount, &prevReplayCount);
        if (ret != SSL_SUCCESS) {
            ret = 1;
            WOLFLOCAL_LOG(2, "getting stats from DTLS session failed.\n");
        }
        else
            ret = 0;
    }
    else {
        WOLFLOCAL_LOG(2, "Tried to get error stats from wrapper NULL\n");
    }

    if (macDropCount != NULL)
        *macDropCount = macCount + prevMacCount +
                        wrapper->macDropCount;
    if (replayDropCount != NULL)
        *replayDropCount = replayCount + prevReplayCount +
                           wrapper->replayDropCount;
    if (epochDropCount != NULL)
        *epochDropCount = wrapper->epochDropCount;

    return ret;
}
