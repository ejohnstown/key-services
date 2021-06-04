#include <pthread.h>
#include "key-services.h"
#include "key-client.h"
#include "key-server.h"

#define KEY_MCAST_PORT 22222
#define KEY_SERV_PORT 11111


typedef struct params_t {
    struct in_addr myAddr;
    struct in_addr mcastAddr;
    void* heap;
} params_t;


static void KeyMcastReqPktCallback(CmdPacket_t* pkt)
{
    if (pkt && pkt->header.type == CMD_PKT_TYPE_DISCOVER) {
        printf("Discovery packet.\n");
    }
}


static void* KeyMcastThread(void* arg)
{
    params_t* params = (params_t*)arg;
    int ret;

    ret = KeyMcast_RunUdp(&params->mcastAddr,
                          KeyMcastReqPktCallback,
                          params->heap);

    return (void*)((size_t)ret);
}


static void* RekeyThread(void* arg)
{
    void* heap = ((params_t*)arg)->heap;
    int ret;

    KeyServices_Init(101, KEY_MCAST_PORT, KEY_SERV_PORT);
    ret = KeyServer_Init(heap, &((params_t*)arg)->myAddr);
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
    pthread_t tid;
    params_t params;

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    if (argc < 3) {
        printf("Usage: %s <address> <mcast address>\n", argv[0]);
        goto exit;
    }

    ret = inet_pton(AF_INET, argv[1], &params.myAddr);
    if (ret != 1) {
        printf("Error: the IP address \'%s\' isn't parsable.\n", argv[1]);
        goto exit;
    }

    ret = inet_pton(AF_INET, argv[2], &params.mcastAddr);
    if (ret != 1) {
        printf("Error: the IP address \'%s\' isn't parsable.\n", argv[2]);
        goto exit;
    }

    params.heap = NULL;

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        printf("Error: wolfSSL_Init\n");
        goto exit;
    }

    KeyServices_Init(102, KEY_MCAST_PORT, KEY_SERV_PORT);
    ret = KeyServer_Init(params.heap, &params.myAddr);
    if (ret != 0) {
        printf("Error: KeyServer_Init\n");
        wolfSSL_Cleanup();
        return ret;
    }

#if 0
    /* spin up another thread for UDP multicast */
    ret = pthread_create(&tid, NULL, KeyMcastThread, &params);
    if (ret < 0) {
        printf("Pthread create failed for UDP\n");
        goto exit;
    }
    pthread_detach(tid);
#endif
    ret = pthread_create(&tid, NULL, RekeyThread, &params);
    if (ret < 0) {
        printf("Pthread create failed for Rekey\n");
        goto exit;
    }
    pthread_detach(tid);

    KeyServer_Resume();
    ret = KeyServer_Run(KeyServerReqPktCallback, 0, params.heap);

exit:

    KeyServer_Free(params.heap);
    wolfSSL_Cleanup();

    return ret;
}
