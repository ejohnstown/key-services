#ifndef _WOLFCAST_H_
#define _WOLFCAST_H_

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

typedef struct wolfWrapper_t wolfWrapper_t; /* Forward reference. */

int WolfcastClientInit(unsigned int *, unsigned int *);
int WolfcastClient(wolfWrapper_t*, unsigned int *, unsigned int *);
int WolfcastServer(wolfWrapper_t*);

#endif /* _WOLFCAST_H_ */
