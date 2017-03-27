#include <wolfssl/wolfcrypt/wc_port.h>
#include "key-socket.h"


#ifndef __KEY_BEACON_H__
#define __KEY_BEACON_H__


typedef struct KeyBeacon_Handle_t KeyBeacon_Handle_t;


typedef enum {
    /* Requested states for AllowFloatingMaster() */
    KB_FM_NOTALLOWED = 0,
    KB_FM_ALLOWED = 1,

    /* Requested actions for FloatingMaster() */
    KB_FM_RELEASE = 0,
    KB_FM_ASSERT = 1,

    /* return codes for FindMaster() */
    KB_FM_OK = 0,
    KB_FM_FAILED = 1,
    KB_FM_WAITING = 2, /* Waiting for a response from the FM. */
} KB_CODES;


KeyBeacon_Handle_t *KeyBeacon_GetGlobalHandle(void);
int KeyBeacon_Handler(KeyBeacon_Handle_t*);

int KeyBeacon_Init(KeyBeacon_Handle_t*);
int KeyBeacon_SetSocket(KeyBeacon_Handle_t*, KS_SOCKET_T, struct sockaddr*);
int KeyBeacon_AllowFloatingMaster(KeyBeacon_Handle_t*, int);
int KeyBeacon_FloatingMaster(KeyBeacon_Handle_t*, int);

int KeyBeacon_FindMaster(KeyBeacon_Handle_t*);
int KeyBeacon_GetMaster(KeyBeacon_Handle_t*, struct in_addr *);


#endif /* __KEY_BEACON_H__ */
