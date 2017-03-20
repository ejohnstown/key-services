#include "key-services.h"


int main(int argc, char **argv)
{
    int ret;
    void* heap = NULL;

    (void)argc;
    (void)argv;

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    wolfSSL_Init();  /* initialize wolfSSL */

    ret = KeyServer_Run(heap);

    wolfSSL_Cleanup();

    return ret;
}
