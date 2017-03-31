#include "key-services.h"

int main(int argc, char **argv)
{
    int ret;
    KeyRespPacket_t keyResp;
    void* heap = NULL;
    char* srvIp;
    struct in_addr srvAddr;

    /* optionally include an ip address of this will flag */
    if (argc != 2) {
        printf("Usage: key-client <server IP>\n");
    }

    XMEMSET(&srvAddr, 0, sizeof(srvAddr));

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
        KeyBeacon_Handle_t *beacon;
        byte* ip = (byte*)&srvAddr.s_addr;

        printf("Finding Key Server\n");

        beacon = KeyBeacon_GetGlobalHandle();
        KeyBeacon_Init(beacon);
        KeyBeacon_FindMaster(beacon);
        KeyBeacon_GetMaster(beacon, &srvAddr);

        printf("Found: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    }

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    wolfSSL_Init();  /* initialize wolfSSL */

    ret = KeyClient_GetKey(&srvAddr, &keyResp, heap);

    wolfSSL_Cleanup();

    return ret;
}
