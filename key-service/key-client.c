#include "key-client.h"
#include "key-server.h"

static volatile int gKeyChg = 0;
static struct in_addr gKeySrvAddr;

#define KEY_BCAST_PORT 22222
#define KEY_SERV_PORT 11111

#define KEY_SERVICE_CLIENT_TIMEOUT (1 * KEY_SERVICE_TICKS_PER_SECOND)


#ifndef NETX
    #include <pthread.h>

    static void KeyBcastReqPktCallback(CmdPacket_t* pkt)
    {
        if (pkt && pkt->header.type == CMD_PKT_TYPE_KEY_CHG) {
            /* trigger key change */
            unsigned char* addr = pkt->msg.keyChgResp.ipaddr;
            XMEMCPY(&gKeySrvAddr.s_addr, addr, sizeof(gKeySrvAddr.s_addr));
            gKeyChg = 1;

            printf("Key Change Server: %d.%d.%d.%d\n",
                addr[0], addr[1], addr[2], addr[3]);
        }
        if (pkt && pkt->header.type == CMD_PKT_TYPE_KEY_USE) {
            printf("SWITCHING!\n");
        }
    }

    static void* KeyBcastThread(void* arg)
    {
        int ret;
        void* heap = arg;
        struct in_addr srvAddr = {-1};

        ret = KeyBcast_RunUdp(&srvAddr, KeyBcastReqPktCallback, heap);

        return (void*)((size_t)ret);
    }
#endif /* !NETX */


int main(int argc, char **argv)
{
    int ret;
    KeyRespPacket_t keyResp;
    void* heap = NULL;
    char* srvIp;
    unsigned char* addr;
    int myId = 0;
#ifndef NETX
    pthread_t tid;
#endif

    XMEMSET(&gKeySrvAddr, 0, sizeof(gKeySrvAddr));

    /* optionally include an ip address of this will flag */
    if (argc != 3) {
        printf("Usage: key-client [id [serverip]]\n");
    }

    if (argc > 1) {
        myId = atoi(argv[1]);
    }

    if (argc > 2) {
        /* parse server IP */
        srvIp = argv[2];

        /* converts IPv4 addresses from text to binary form */
        ret = inet_pton(AF_INET, srvIp, &gKeySrvAddr);
        if (ret != 1) {
            printf("inet_pton error %d\n", ret);
            return -1;
        }
    }
    else {
        /* use broadcast */
        gKeySrvAddr.s_addr = -1;
    }

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        printf("Error: wolfSSL_Init\n");
        goto exit;
    }

    KeyServices_Init(myId, KEY_BCAST_PORT, KEY_SERV_PORT);
    ret = KeyServer_Init(heap, &gKeySrvAddr);
    if (ret != 0) {
        printf("Error: KeyServer_Init\n");
        wolfSSL_Cleanup();
        return ret;
    }

#ifndef NETX
    /* spin up another thread for UDP broadcast */
    ret = pthread_create(&tid, NULL, KeyBcastThread, heap);
    if (ret < 0) {
        printf("Pthread create failed for UDP\n");
        goto exit;
    }
    pthread_detach(tid);
#endif

    ret = KeyClient_FindMaster(&gKeySrvAddr, heap);
    if (ret != 0) {
        printf("unable to find master %d\n", ret);
        goto exit;
    }
    addr = (unsigned char*)&gKeySrvAddr.s_addr;
    printf("Found Server: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);


restart:

    ret = KeyClient_GetKey(&gKeySrvAddr, &keyResp, heap);
    printf("KeyClient_GetKey: ret %d\n", ret);

    while (gKeyChg == 0) {
        KEY_SERVICE_SLEEP(KEY_SERVICE_CLIENT_TIMEOUT);
    }

exit:

    if (gKeyChg) {
        gKeyChg = 0;
        printf("Key Change\n");
        goto restart;
    }

    wolfSSL_Cleanup();
    KeyServer_Free(heap);

    return ret;
}
