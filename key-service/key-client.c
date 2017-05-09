#include "key-services.h"

#ifndef NETX
    #include <pthread.h>
    static void* KeyBcastThread(void* arg)
    {
        int ret;
        void* heap = arg;
        const unsigned char bcast_addr[] = {KEY_BCAST_ADDR};
        struct in_addr srvAddr;
        XMEMCPY(&srvAddr.s_addr, bcast_addr, sizeof(srvAddr.s_addr));

        ret = KeyBcast_RunUdp(&srvAddr, heap);

        return (void*)((size_t)ret);
    }
#endif /* !NETX */

int main(int argc, char **argv)
{
    int ret;
    KeyRespPacket_t keyResp;
    void* heap = NULL;
    char* srvIp;
    struct in_addr srvAddr;
    unsigned char* addr;
    const unsigned char bcast_addr[] = {KEY_BCAST_ADDR};
#ifndef NETX
    pthread_t tid;
#endif

    XMEMSET(&srvAddr, 0, sizeof(srvAddr));

    /* optionally include an ip address of this will flag */
    if (argc != 2) {
        printf("Usage: key-client <server IP>\n");
    }

    if (argc > 1) {
        /* parse server IP */
        srvIp = argv[1];

        /* converts IPv4 addresses from text to binary form */
        ret = inet_pton(AF_INET, srvIp, &srvAddr);
        if (ret != 1) {
            printf("inet_pton error %d\n", ret);
            return -1;
        }
    }
    else {
        /* use broadcast */
        XMEMCPY(&srvAddr.s_addr, bcast_addr, sizeof(srvAddr.s_addr));
    }

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

    ret = KeyClient_FindMaster(&srvAddr, heap);
    if (ret != 0) {
        printf("unable to find master %d\n", ret);
        goto exit;
    }
    addr = (unsigned char*)&srvAddr.s_addr;
    printf("Found Server: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);

    ret = KeyClient_GetKey(&srvAddr, &keyResp, heap);
    printf("KeyClient_GetKey: ret %d\n", ret);

#ifndef NETX
    /* spin up another thread for UDP broadcast */
    ret = pthread_create(&tid, NULL, KeyBcastThread, heap);
    if (ret < 0) {
        printf("Pthread create failed for UDP\n");
        goto exit;
    }
#endif

#ifndef NETX
    pthread_join(tid, NULL);
#endif

exit:

    wolfSSL_Cleanup();
    KeyServer_Free(heap);

    return ret;
}
