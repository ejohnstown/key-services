#include "types.h"
#include "wolflocal.h"
#include "key-client.h"
#include "key-server.h"
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

//#define SERVER_ID 5
//#define FOREIGN_CLIENT_ID 23

#ifndef WOLFLOCAL_KEY_NEW_TIME
//	#define WOLFLOCAL_KEY_NEW_TIME 15
	#define WOLFLOCAL_KEY_NEW_TIME 10
#endif
#ifndef WOLFLOCAL_KEY_USE_TIME
//	#define WOLFLOCAL_KEY_USE_TIME 15
	#define WOLFLOCAL_KEY_USE_TIME 4
#endif
#ifndef WOLFLOCAL_KEY_CHANGE_PERIOD
//	#define WOLFLOCAL_KEY_CHANGE_PERIOD 60
	#define WOLFLOCAL_KEY_CHANGE_PERIOD 15
#endif
#if WOLFLOCAL_KEY_CHANGE_PERIOD <= WOLFLOCAL_KEY_NEW_TIME + WOLFLOCAL_KEY_USE_TIME
#error "WOLFLOCAL_KEY_CHANGE_PERIOD too small"
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

#if defined(NETX) && defined(__RX__)
    #define MEMORY_SECTION_BSS  LINK_SECTION(bss_sdram)
	#define MEMORY_SECTION_DATA LINK_SECTION(data_sdram)
#else
	#define MEMORY_SECTION_BSS
	#define MEMORY_SECTION_DATA
#endif

static TX_THREAD gKeyBcastUdpThread;
#ifndef WOLFLOCAL_NO_KEY_CLIENT
static TX_THREAD gKeyClientThread;
#endif
#ifndef WOLFLOCAL_NO_KEY_SERVER
static TX_THREAD gKeyServerThread;
#endif

static char gKeyBcastUdpStack[KS_STACK_SZ];
#ifndef WOLFLOCAL_NO_KEY_CLIENT
static char gKeyClientStack[KS_STACK_SZ];
#endif
#ifndef WOLFLOCAL_NO_KEY_SERVER
static char gKeyServerStack[KS_STACK_SZ];
MEMORY_SECTION_BSS static unsigned char gKeyServiceMemory[KS_MEMORY_POOL_SZ];
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    MEMORY_SECTION_BSS unsigned char gWolfCastMemory[WOLFLOCAL_STATIC_MEMORY_SZ];
    MEMORY_SECTION_DATA UCHAR *heap_address = gWolfCastMemory;
    MEMORY_SECTION_DATA UINT	heap_size = WOLFLOCAL_STATIC_MEMORY_SZ;
#endif


/* Mutex for controlling the current key state. The Key
 * Client thread will be writing to the key state and
 * the wolfCast client will be reading it. Also, the
 * wolfCast client will set a semaphore to for the Key
 * Client to request a new key. */
static TX_MUTEX gKeyStateMutex;
static TX_MUTEX gSslMutex;
static TX_EVENT_FLAGS_GROUP gEventFlags;
MEMORY_SECTION_BSS UINT gKeySet = 0;
MEMORY_SECTION_DATA UINT gGetNewKey = 1;
MEMORY_SECTION_BSS  UINT gRekeyNow = 0;
MEMORY_SECTION_BSS UINT gRequestRekey = 0;
//MEMORY_SECTION_DATA static UINT gFindMaster = 1;
MEMORY_SECTION_DATA UINT gSwitchKeys = 0;
MEMORY_SECTION_BSS KeyRespPacket_t gKeyState;
MEMORY_SECTION_BSS static WOLFSSL_HEAP_HINT *gHeapHint = NULL;
MEMORY_SECTION_BSS struct in_addr gKeySrvAddr = { 0 };
MEMORY_SECTION_BSS static UINT gNewKeyCount = 0;
MEMORY_SECTION_BSS static UINT gUseKeyCount = 0;
MEMORY_SECTION_BSS wolfWrapper_t *gWrapper;
MEMORY_SECTION_BSS ULONG gAddr = 0;
MEMORY_SECTION_BSS ULONG gMask = 0;

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

static int wolfWrapper_Update(wolfWrapper_t* wrapper, unsigned short epoch)
{
    UINT status;
    int error = 0;
    WOLFSSL *newSsl;

    if (wrapper == NULL) {
        return 1;
    }

    status = tx_mutex_get(&gKeyStateMutex, TX_WAIT_FOREVER);
    if (status != TX_SUCCESS) {
    	WOLFLOCAL_LOG(1, "%s: tx_mutex_get error = %u\n", __func__, status);
    	return 1;
    }

    // Update not already done from another thread.
    if (epoch != wrapper->epoch)
    {
		memcpy(&wrapper->keyState, &gKeyState, sizeof(gKeyState));

		status = wolfWrapper_NewSession(wrapper, &newSsl);
		if (status != 0) {
			WOLFLOCAL_LOG(1, "%s: wolfWrapper_NewSession error = %u\n", __func__, status);
			error = 1;
		}
		else {
			status = wolfSSL_set_secret(newSsl, epoch,
										wrapper->keyState.pms,
										sizeof(wrapper->keyState.pms),
										wrapper->keyState.clientRandom,
										wrapper->keyState.serverRandom,
										wrapper->keyState.suite);
			if (status != SSL_SUCCESS) {
				WOLFLOCAL_LOG(1, "%s: wolfWrapper_NewSession error = %u\n", __func__, status);
				error = 1;
				wolfSSL_free(newSsl);
			}
			else {
				memset(&wrapper->keyState, 0, sizeof(wrapper->keyState));

				status = tx_mutex_get(&gSslMutex, TX_WAIT_FOREVER);
				if (status == TX_SUCCESS)
				{
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
					wrapper->epoch = epoch;
				}
				else
				{
					WOLFLOCAL_LOG(1, "Couldn't get SSL mutex %u\n", status);
					wolfSSL_free(newSsl);
				}
				(void) tx_mutex_put(&gSslMutex);
			}
		}
    }
	(void) tx_mutex_put(&gKeyStateMutex);

    return error;
}

void WolfLocalRekey(void)
{
    if (KeyServer_IsRunning())
    {
    	if (gNewKeyCount == 0)
    	{
    		gRekeyNow = 1;
    	}
    	else
    	{
			gNewKeyCount = WOLFLOCAL_KEY_NEW_TIME;
			gUseKeyCount = 0;
    	}
    }
    else
    {
    	if (gKeySrvAddr.s_addr != 0)
    	{
//    		gFindMaster = 1;
//   		gRequestRekey = 1;
    	}
    }
}

static int isAddrSet(void)
{
    int isSet = 0;
    UINT status;
    ULONG actual_status, addr, mask;

    if (nxIp == NULL) {
        WOLFLOCAL_LOG(1, "nxIp == NULL\n");
    }
    else {
    	status = nx_ip_status_check(nxIp, NX_IP_INITIALIZE_DONE, &actual_status, NX_WAIT_FOREVER);
        if (status == NX_SUCCESS && (actual_status & NX_IP_INITIALIZE_DONE) == NX_IP_INITIALIZE_DONE) {
			status = nx_ip_address_get(nxIp, &addr, &mask);
			if (status == NX_SUCCESS) {
				if (addr != 0 && (addr & 0xFFFF0000UL) != IP_ADDRESS(169,254,0,0)) {

					gAddr = addr;
					gMask = mask;
					isSet = 1;
				}
				else {
			        WOLFLOCAL_LOG(1, "nx_ip_address_get address == %hhu.%hhu.%hhu.%hhu\n",
			        			  BYTE3_OF(addr), BYTE2_OF(addr), BYTE1_OF(addr), BYTE0_OF(addr));
				}
			}
			else {
		        WOLFLOCAL_LOG(1, "nx_ip_address_get status == %u\n", status);
			}
        }
    }

    return isSet;
}


static void
keyServerCb(CmdPacket_t* pkt)
{
    if (pkt &&
        pkt->header.type == CMD_PKT_TYPE_KEY_NEW &&
        gNewKeyCount == 0 &&
        gWrapper->curSsl != NULL &&
        wolfSSL_mcast_peer_known(gWrapper->curSsl, pkt->header.id)) {

    	gRekeyNow = 1;
    }
}

#ifndef WOLFLOCAL_NO_KEY_SERVER
/* KeyServerEntry
 * Thread entry point to drive the key server. Key server really
 * shouldn't ever return, but the return code is checked and
 * reported, just in case. */
static void
KeyServerEntry(ULONG ignore)
{
    ULONG flags = 0;
    int result;

    (void)ignore;

    result = tx_event_flags_get(&gEventFlags, (KS_EVENT_HEAP | KS_EVENT_ADDR),
                                TX_AND, &flags, TX_WAIT_FOREVER);
    if (result == TX_SUCCESS)
        WOLFLOCAL_LOG(3, "KeyServerEntry got the start event (%u)\n", flags);
    else
        WOLFLOCAL_LOG(1, "KeyServerEntry failed to get event flags\n");

    {
        struct in_addr inaddr;
        inaddr.s_addr = gAddr;
        result = KeyServer_Init(gHeapHint, &inaddr);
        if (result != 0) {
            WOLFLOCAL_LOG(1, "KeyServer couldn't initialize. (%d)\n", result);
        }
    }

    if (result == 0) {
        result = KeyServer_Run(keyServerCb, KEY_SERVICE_TCP_CLIENTS, gHeapHint);
        if (result != 0) {
            WOLFLOCAL_LOG(2, "KeyServer terminated. (%d)\n", result);
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
    unsigned short epoch;

	if (pkt != NULL) {
		switch (pkt->header.type) {
			case CMD_PKT_TYPE_KEY_CHG:
				/* trigger key change */
				msg = pkt->msg.keyChgResp.ipaddr;
				msg = pkt->msg.keyChgResp.epoch;
				epoch = (msg[0] << 8) | msg[1];
				if (epoch != ((gKeyState.epoch[0] << 8) | gKeyState.epoch[1])) {
					gGetNewKey = 1;
				}
				break;
			case CMD_PKT_TYPE_KEY_USE:
				/* switch to new key */
				msg = pkt->msg.epochResp.epoch;
				epoch = (msg[0] << 8) | msg[1];
				if (epoch != gWrapper->epoch) {
					if (epoch == ((gKeyState.epoch[0] << 8) | gKeyState.epoch[1])) {
						wolfWrapper_Update(gWrapper, epoch);
					}
					else {
				        WOLFLOCAL_LOG(3, "Use Key epoch = %hu, keyState = %hu\n", epoch,
				        		(unsigned short)(gKeyState.epoch[0] << 8) | gKeyState.epoch[1]);
						gGetNewKey = 1;
					}
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

    {
        ULONG flags;
        result = tx_event_flags_get(&gEventFlags, KS_EVENT_HEAP,
                                    TX_AND, &flags, TX_WAIT_FOREVER);
        if (result == TX_SUCCESS)
            WOLFLOCAL_LOG(3, "KeyBcastUdpEntry got the start event (%u)\n",
                          flags);
        else
            WOLFLOCAL_LOG(1, "KeyBcastUdpEntry failed to get event flags\n");
    }

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    if (wolfSSL_Init() != SSL_SUCCESS) {
        WOLFLOCAL_LOG(1, "KeyBcastUdpEntry couldn't initialize wolfSSL.\n");
    }

    while (!isAddrSet()) {
        WOLFLOCAL_LOG(3, "KeyBcastUdpEntry waiting for network.\n");
        tx_thread_sleep(KS_TIMEOUT_NETWORK_READY);
    }

    tx_event_flags_set(&gEventFlags, KS_EVENT_ADDR, TX_OR);

    result = KeyBcast_RunUdp(&gGroupAddr, broadcastCb, gHeapHint);
    if (result != 0) {
        WOLFLOCAL_LOG(2, "KeyBcastUdp terminated. (%d)\n", result);
    }
}


#ifndef WOLFLOCAL_NO_KEY_CLIENT
/* KeyClientEntry
 * Thread entry point to drive the key client. It initializes wolfSSL for
 * its use, waits for the network interface to be ready, then it loops
 * trying to get key updates. */
static void
KeyClientEntry(ULONG ignore)
{
    ULONG flags = 0;
    int result;
//    UINT findMaster = 0;
    UINT requestRekey = 0;
    UINT getNewKey = 0;
    volatile UINT storeKey = 0; // volatile due to compiler optimizer bug
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
        if (/*!findMaster && */ !requestRekey && !getNewKey && !storeKey) {
//            findMaster = gFindMaster;
//            gFindMaster = 0;
        	getNewKey = gGetNewKey;
        	gGetNewKey = 0;
        	requestRekey = gRequestRekey;
        	gRequestRekey = 0;
        }

//        if (findMaster) {
//			gKeySrvAddr = gGroupAddr;
//			result = KeyClient_FindMaster(&gKeySrvAddr, gHeapHint);
//			if (result != 0) {
//				WOLFLOCAL_LOG(3, "Key server didn't announce itself.\n");
//			}
//			else
//			{
//				findMaster = 0;
//			}
//        }

        if (/*!findMaster && */ gKeySrvAddr.s_addr != 0 && requestRekey && !storeKey) {
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

        if (/*!findMaster && */ gKeySrvAddr.s_addr != 0 && getNewKey && !storeKey) {
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
            status = tx_mutex_get(&gKeyStateMutex, TX_WAIT_FOREVER);
            if (status == TX_SUCCESS) {
                memcpy(&gKeyState, &keyResp, sizeof(KeyRespPacket_t));
                KeyServer_SetKeyResp(&gKeyState, gHeapHint);
                gKeySet = 1;
                storeKey = 0;
                tx_mutex_put(&gKeyStateMutex);
                WOLFLOCAL_LOG(3, "Key client got key, epoch = %hu\n", *(USHORT *)keyResp.epoch);
            }
            else {
                WOLFLOCAL_LOG(2, "Couldn't get key state mutex to write\n");
            }
        }

        tx_thread_sleep(KS_TIMEOUT_KEY_CLIENT);
    }
}
#endif

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
                             TX_INHERIT);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key state mutex create failed = 0x%02X\n", status);
        return;
    }

    status = tx_mutex_create(&gSslMutex, "SSL mutex",
                             TX_INHERIT);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "SSL mutex create failed = 0x%02X\n", status);
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

#ifndef WOLFLOCAL_NO_KEY_SERVER
   status = tx_thread_create(&gKeyServerThread, "key service server",
                           KeyServerEntry, 0,
                           gKeyServerStack, sizeof(gKeyServerStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key server thread create failed = 0x%02X\n", status);
        return;
    }
#endif

#ifndef WOLFLOCAL_NO_KEY_CLIENT
    status = tx_thread_create(&gKeyClientThread, "key service client",
                           KeyClientEntry, 0,
                           gKeyClientStack, sizeof(gKeyClientStack),
                           KS_PRIORITY, KS_THRESHOLD,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS) {
        WOLFLOCAL_LOG(1, "key client thread create failed = 0x%02X\n", status);
        return;
    }
#endif

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

    WOLFLOCAL_LOG(3, "timer: %u\n", count);

    if (!KeyServer_IsRunning())
    {
    	gNewKeyCount = 0;
    	gUseKeyCount = 0;
    }
    else
    {
		/* Every X seconds on the 0, ... */
		if (((count % WOLFLOCAL_KEY_CHANGE_PERIOD) == 0  && !gNewKeyCount && !gUseKeyCount) || gRekeyNow) {
			WOLFLOCAL_LOG(3, "timer: key change counter %% %u == 0\n", WOLFLOCAL_KEY_CHANGE_PERIOD);
			if (gNewKeyCount == 0) {
				ret = KeyServer_GenNewKey(gHeapHint);
				WOLFLOCAL_LOG(3, "timer: announcing the new key, epoch = %hu\n", gKeyServerEpoch);
				if (ret) {
					WOLFLOCAL_LOG(1, "Failed to announce new key.\n");
				}
				else {
					gRekeyNow = 0;
					gGetNewKey = 1;
					gNewKeyCount = WOLFLOCAL_KEY_NEW_TIME;
					gUseKeyCount = 0;
				}
			}
			else {
	#ifdef WOLFLOCAL_TEST_KEY_REQUEST
				gRequestRekey = 1;
	#endif /* WOLFLOCAL_TEST_KEY_REQUEST */
			}
		}
		/* If the switch key count is set, decrement it. If it becomes 0,
		 * switch the keys. */
		else if (gNewKeyCount) {
			gNewKeyCount--;
			if (gNewKeyCount != 0) {
				WOLFLOCAL_LOG(3, "timer: reannouncing the new key %u left, epoch = %hu\n", gNewKeyCount - 1, gKeyServerEpoch);
				KeyServer_NewKeyChange(gHeapHint);
			}
			else {
				gUseKeyCount = WOLFLOCAL_KEY_USE_TIME;
				WOLFLOCAL_LOG(3, "timer: announcing the use key, epoch = %hu\n", gKeyServerEpoch);
				ret = KeyServer_NewKeyUse(gHeapHint);
				if (ret) {
					WOLFLOCAL_LOG(1, "Failed to announce key switch.\n");
				}
				else {
					wolfWrapper_Update(gWrapper, gKeyServerEpoch);
				}
			}
		}

		else if (gUseKeyCount) {
			gUseKeyCount--;
			if (gUseKeyCount != 0) {
				WOLFLOCAL_LOG(3, "timer: reannouncing the use key %u left, epoch = %hu\n", gUseKeyCount - 1, gKeyServerEpoch);
				ret = KeyServer_NewKeyUse(gHeapHint);
				if (ret) {
					WOLFLOCAL_LOG(1, "Failed to announce key switch.\n");
				}
			}
			else {
				WOLFLOCAL_LOG(3, "timer: end of use, epoch = %hu\n", gKeyServerEpoch);
			}
		}
    }

    if ((count % WOLFLOCAL_STATS_PERIOD) == 0) {
        unsigned int ks, mac, replay, epoch;

        ks = KeyServer_GetAuthFailCount();
        WOLFLOCAL_LOG(3, "Key Server auth fail counts: %u\n", ks);

		wolfWrapper_GetErrorStats(gWrapper, &mac, &replay, &epoch);
		WOLFLOCAL_LOG(3, "Wrapper macFail: %u\n"
				  	     "    replayCount: %u\n"
				  	  	 "      epochDrop: %u\n",
				  	  	 mac, replay, epoch);
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

// Debug message sequence
#if 0
	static uint32 expected_seq;
	static uint16 old_epoch;
	uint16 new_epoch = *(uint16 *)(buf + 3);
	uint32 new_seq = *(uint32 *)(buf + 7);
	if (new_epoch == old_epoch)
	{
		if (new_seq != expected_seq)
		{
			bsp_debug_printf("%s: epoch = %hu\tseq = %u\t expected = %u\n",
							 __func__, new_epoch, new_seq, expected_seq);
		}
		if (new_seq >= expected_seq)
		{
			expected_seq = new_seq + 1;
		}
	}
	else
	{
		old_epoch = new_epoch;
		expected_seq = new_seq + 1;
	}
#endif

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
        status = NX_PTR_ERROR;
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
        status = NX_OVERFLOW;
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
    wrapper->ip = BSP_IP_POINTER;
    wrapper->pool = BSP_POOL_POINTER;

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

    ret = nx_igmp_loopback_disable(wrapper->ip);
    if (ret == NX_NOT_ENABLED) {
        WOLFLOCAL_LOG(3, "IGMP loopback already disabled\n");
    }
    else if (ret != NX_SUCCESS) {
        WOLFLOCAL_LOG(1, "cannot disable IGMP loopback\n");
        goto exit;
    }

    /* Wait for the first key. */
    while (!gKeySet) {
        WOLFLOCAL_LOG(3, "wolfWrapper_Init waiting for first key.\n");
        tx_thread_sleep(KS_TIMEOUT_WOLFLOCAL_KEY_POLL);
    }
	wolfWrapper_Update(wrapper, (gKeyState.epoch[0] << 8) | gKeyState.epoch[1]);
    WOLFLOCAL_LOG(3, "wolfCast got key set flag, epoch = %hu\n", gSwitchKeys);

exit:
    return ret;
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
    if (wrapper == NULL || wrapper->curSsl == NULL || buf == NULL || sz == 0)
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

    *recvSz = -1;
    if (wrapper != NULL && buf != NULL && sz != 0)
    {
        wrapper->rxPacket = nxPacket;
		epoch = GetEpoch(nxPacket);
		if (epoch != wrapper->epoch && epoch == ((gKeyState.epoch[0] << 8) | gKeyState.epoch[1]))
		{
			/* We may have missed a switch keys. */
			WOLFLOCAL_LOG(2, "%s: switch keys epoch = %hu\n", __func__, epoch);
			wolfWrapper_Update(wrapper, epoch);
		}
        status = tx_mutex_get(&gSslMutex, TX_WAIT_FOREVER);
        if (status == TX_SUCCESS) {
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
									WOLFLOCAL_LOG(2, "Allowable DTLS error. Ignoring a message.\n");
								}
								else // if (status != SSL_ERROR_WANT_READ)
								{
									WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
											  wolfSSL_ERR_reason_error_string(status));
								}
							}
						}
						else
						{
							WOLFLOCAL_LOG(2, "Allowable DTLS error. Ignoring a message.\n");
						}
					}
					else // if (status != SSL_ERROR_WANT_READ)
					{
						WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
								  wolfSSL_ERR_reason_error_string(status));
					}
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
						WOLFLOCAL_LOG(2, "Allowable DTLS error. Ignoring a message.\n");
					}
					else // if (status != SSL_ERROR_WANT_READ)
					{
						WOLFLOCAL_LOG(1, "wolfSSL error: %s\n",
								  wolfSSL_ERR_reason_error_string(status));
					}
				}
			}
			if (status > 0)
			{
				*recvSz = status;
			}
			else
			{
				if (status == 0)
				{
					WOLFLOCAL_LOG(2, "Ignoring message unknown Epoch %hu Have %hu & %hu\n", epoch, wrapper->prevEpoch, wrapper->epoch);
					wrapper->epochDropCount++;
				}
			}
	    }
    	(void) tx_mutex_put(&gSslMutex);
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

    if (wrapper != NULL && wrapper->curSsl != NULL) {
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
