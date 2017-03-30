#include "key-services.h"
#include "key-beacon.h"

#ifndef NETX
    /* additional *nix headers needed for threading, select and time */
    #include <sys/select.h>
    #include <sys/time.h>
    #include <pthread.h>
#endif

#ifndef NETX
static void* KeyServerUdpThread(void* arg)
{
    KeyBeacon_Handle_t *h;
    KS_SOCKET_T s = KS_SOCKET_T_INIT;
    int error = 0;
    struct sockaddr_in groupAddr;
    struct in_addr myAddr;
    int enabled = 1;
    (void)arg;
printf("KeyServerUdpThread...\n");
    memset(&groupAddr, 0, sizeof(groupAddr));
    memset(&myAddr, 0, sizeof(myAddr));
    
    groupAddr.sin_family = AF_INET;
    groupAddr.sin_port = htons(SERV_PORT);
    groupAddr.sin_addr.s_addr = inet_addr("192.168.2.255");
    myAddr.s_addr = inet_addr("192.168.2.1");

    KeySocket_CreateUdpSocket(&s);
    KeySocket_Bind(s, &myAddr, SERV_PORT);
    KeySocket_SetSockOpt(s, SOL_SOCKET, SO_BROADCAST,
        &enabled, sizeof(enabled));
    KeySocket_SetNonBlocking(s);
    h = KeyBeacon_GetGlobalHandle();
    KeyBeacon_Init(h);
    KeyBeacon_AllowFloatingMaster(h, 1);
    KeyBeacon_FloatingMaster(h, 1);
    KeyBeacon_SetSocket(h, s, (struct sockaddr*)&groupAddr, &myAddr);
printf("about to loop forever\n");
    while (!error) {
        error = KeyBeacon_Handler(h);
        printf("Sleeping\n");
        sleep(1);
    }

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
