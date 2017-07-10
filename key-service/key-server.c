#include <pthread.h>
#include "key-services.h"

static const unsigned char gBcastAddr[] = {KEY_BCAST_ADDR};
#define KEY_BCAST_PORT 22222
#define KEY_SERV_PORT 11111

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


static void* RekeyThread(void* arg)
{
    int ret;
    void* heap = arg;

    while (1) {
        sleep(30);
        printf("Generating and announcing new key.\n");
        ret = KeyServer_GenNewKey(heap);
        if (ret != 0) {
            printf("KeyServer_GenNewKey() failed, ret = %d\n", ret);
            break;
        }

        sleep(5);
        printf("SWITCH!\n");
        ret = KeyServer_NewKeyUse(heap);
        if (ret != 0) {
            printf("KeyServer_NewKeyUse() failed, ret = %d\n", ret);
            break;
        }
    }

    printf("Rekey Thread failed and exited.\n");

    return (void*)((size_t)ret);
}


static void KeyServerReqPktCallback(CmdPacket_t* pkt)
{
    if (pkt == NULL)
        return;

    if (pkt->header.type == CMD_PKT_TYPE_KEY_REQ) {
        printf("Key request.\n");
    }

    if (pkt->header.type == CMD_PKT_TYPE_KEY_NEW) {
        printf("Rekey request.\n");
    }
}


int main(int argc, char **argv)
{
    int ret = 0;
    void* heap = NULL;
    pthread_t tid;
    struct in_addr myAddr;

    (void)argc;
    (void)argv;

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    inet_pton(AF_INET, "192.168.1.154", &myAddr);
    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        printf("Error: wolfSSL_Init\n");
        goto exit;
    }

    ret = KeyServer_Init(heap, &myAddr, KEY_BCAST_PORT, KEY_SERV_PORT);
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

    ret = pthread_create(&tid, NULL, RekeyThread, heap);
    if (ret < 0) {
        printf("Pthread create failed for Rekey\n");
        goto exit;
    }
    pthread_detach(tid);

    KeyServer_Resume();
    ret = KeyServer_Run(KeyServerReqPktCallback, heap);

exit:

    KeyServer_Free(heap);
    wolfSSL_Cleanup();

    return ret;
}
