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
    int ret = 0;
    void* heap = NULL;
#ifndef NETX
    pthread_t tid;
#endif

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

#ifndef NETX
    /* spin up another thread for UDP broadcast */
    ret = pthread_create(&tid, NULL, KeyBcastThread, heap);
    if (ret < 0) {
        printf("Pthread create failed for UDP\n");
        goto exit;
    }
#endif

    ret = KeyServer_Run(heap);

#ifndef NETX
    pthread_join(tid, NULL);

exit:
#endif

    wolfSSL_Cleanup();
    KeyServer_Free(heap);

    return ret;
}
