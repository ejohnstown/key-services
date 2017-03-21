#include "key-services.h"

#ifndef NETX
    /* additional *nix headers needed for threading, select and time */
    #include <sys/select.h>
    #include <sys/time.h>
    #include <pthread.h>
#endif

#ifndef NETX
static void* KeyServerUdpThread(void* arg)
{
    void* heap = arg;
    KeyServer_RunUdp(heap);
    return NULL;
}
#endif

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

    wolfSSL_Init();  /* initialize wolfSSL */

#ifndef NETX
    /* spin up another server for UDP */
    ret = pthread_create(&tid, NULL, KeyServerUdpThread, NULL);
    if (ret < 0) {
        printf("Pthread create failed for UDP\n");
    }
#endif

    if (ret >= 0)
        ret = KeyServer_Run(heap);

#ifndef NETX
    pthread_join(tid, NULL);
#endif

    wolfSSL_Cleanup();

    return ret;
}
