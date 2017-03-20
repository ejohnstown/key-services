#include "types.h"
#include "wolflocal.h"


int mySeed(unsigned char* output, unsigned int sz)
{
    unsigned int i;

    srand(bsp_fast_timer_uptime());
    for (i = 0; i < sz; i++ ) {
        output[i] = rand() % 256;
        if ((i % 8) == 7) {
            srand(bsp_fast_timer_uptime());
        }
    }

    return 0;

}


unsigned int LowResTimer(void)
{
    return(tx_time_get() / 100);
}
