#include "key-services.h"

int main(int argc, char **argv)
{
    int ret = 0;
    void* heap = NULL;

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

    ret = KeyServer_Run(heap);

exit:

    KeyServer_Free(heap);
    wolfSSL_Cleanup();

    return ret;
}
