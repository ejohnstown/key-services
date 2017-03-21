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

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    wolfSSL_Init();  /* initialize wolfSSL */

    ret = KeyClient_FindMaster(&srvAddr, heap);
    if (ret != 0) {
        printf("unable to find master %d\n", ret);
    }

    ret = KeyClient_GetKey(&srvAddr, &keyResp, heap);

    wolfSSL_Cleanup();

    return ret;
}
