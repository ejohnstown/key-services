#include <pthread.h>
#include "key-services.h"

static const unsigned char gBcastAddr[] = {KEY_BCAST_ADDR};

static void KeyBcastReqPktCallback(CmdPacket_t* pkt)
{
    if (pkt && pkt->header.type == CMD_PKT_TYPE_DISCOVER) {
        printf("Discovery packet.\n");
    }
}


static void* KeyBcastThread(void* arg)
{
    int ret;
    void* heap = arg;
    struct in_addr srvAddr;
    XMEMCPY(&srvAddr.s_addr, gBcastAddr, sizeof(srvAddr.s_addr));

    ret = KeyBcast_RunUdp(&srvAddr, KeyBcastReqPktCallback, heap);

    return (void*)((size_t)ret);
}


int main(int argc, char **argv)
{
    int ret = 0;
    void* heap = NULL;
    pthread_t tid;

    (void)argc;
    (void)argv;

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        printf("Error: wolfSSL_Init\n");
        goto exit;
    }

    ret = KeyServer_Init(heap);
    if (ret != 0) {
        printf("Error: KeyServer_Init\n");
        wolfSSL_Cleanup();
        return ret;
    }

    /* spin up another thread for UDP broadcast */
    ret = pthread_create(&tid, NULL, KeyBcastThread, heap);
    if (ret < 0) {
        printf("Pthread create failed for UDP\n");
        goto exit;
    }
    pthread_detach(tid);

    ret = KeyServer_Run(heap);

exit:

    KeyServer_Free(heap);
    wolfSSL_Cleanup();

    return ret;
}
