#include "key-beacon.h"


#define KB_PRINTF printf

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#define KEY_BEACON_LOGGING_LEVEL 2


typedef enum KeyBeacon_State_t {
    KBS_invalid,
    KBS_init,
    KBS_master,
    KBS_client
} KeyBeacon_State_t;


struct KeyBeacon_Handle_t {
    wolfSSL_Mutex mutex;
    KS_SOCKET_T socket;
    KS_SOCKET_T socketReq;
    KeyBeacon_State_t state;
    KeyBeacon_State_t stateReq;
    int fmAllowed; /* This KeyBeacon is allowed to become floating master */
    int fmAllowedReq; /* request change to being able to be floating master */
    int fmKnown; /* floating master location known */
    int fmReq;   /* request to find the master */
    struct in_addr fmAddr; /* floating master's address */
    struct sockaddr groupAddr; /* key beacon group address */
    struct sockaddr groupAddrReq;
    unsigned short port;
    unsigned short portReq;
};


#define KB_MSGID_WHOISFM 0x55
#define KB_MSGID_IAMFM 0xAA


static KeyBeacon_Handle_t beaconHandle;


/* KeyBeacon_Init
 * Should be called before threading starts so the mutex is set up.
 * Initializes the KeyBeacon state, and sets up the mutex. */
int KeyBeacon_Init(KeyBeacon_Handle_t *h)
{
    int result;
    int error = 0;

    if (h == NULL) {
        KB_PRINTF("KeyBeacon_Init error: no handle\n");
        error = 1;
    }

    if (!error) {
        memset(h, 0, sizeof(KeyBeacon_Handle_t));
        h->state = KBS_invalid;

        result = wc_InitMutex(&h->mutex);
        if (result != 0) {
            KB_PRINTF("KeyBeacon_Init error: couldn't init mutex\n");
            error = 1;
        }
    }

    if (!error) {
        h->state = KBS_init;
        h->stateReq = KBS_client;
        h->fmAllowed = KB_FM_NOTALLOWED;
        h->fmAllowedReq = KB_FM_NOTALLOWED;
    }

    return error;
}


/* KeyBeacon_GetGlobalHandle
 * Returns the static-global key beacon handler object. */
KeyBeacon_Handle_t *KeyBeacon_GetGlobalHandle(void)
{
    return &beaconHandle;
}


/* KeyBeacon_AllowFloatingMaster
 * Allows or disallows h to become a floating master. A Key Beacon handler
 * is initialized so it cannot be a floating master, this method allows it
 * to. */
int KeyBeacon_AllowFloatingMaster(KeyBeacon_Handle_t* h, int allow)
{
    int error = 0;
    int locked = 0;

    if (h == NULL) {
        KB_PRINTF("KeyBeacon_AllowFloatingMaster error: invalid parameter\n");
        error = 1;
    }

    if (!error) {
        if (wc_LockMutex(&h->mutex) != 0) {
            KB_PRINTF("KeyBeacon_FloatingMaster error: couldn't lock mutex\n");
            error = 1;
        }
        else
            locked = 1;
    }

    if (!error) {
        h->fmAllowedReq = (allow == KB_FM_NOTALLOWED) ?
                              KB_FM_NOTALLOWED : KB_FM_ALLOWED;
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    return error;
}


/* KeyBeacon_SetSocket
 * Sets the socket for the beacon. While the beacon will handle reads and
 * writes, the owner should control the socket. */
int KeyBeacon_SetSocket(KeyBeacon_Handle_t* h, KS_SOCKET_T socket,
                        struct sockaddr* addr)
{
    int error = 0;
    int locked = 0;

    if (h == NULL || socket == 0) {
        KB_PRINTF("KeyBeacon_SetSocket: invalid parameters\n");
        error = 1;
    }

    if (!error) {
        if (wc_LockMutex(&h->mutex) != 0) {
            KB_PRINTF("KeyBeacon_SetSocket error: couldn't lock mutex\n");
            error = 1;
        }
        else
            locked = 1;
    }

    if (!error) {
        h->socketReq = socket;
        h->portReq = ((struct sockaddr_in*)addr)->sin_port;
        memcpy(&h->groupAddrReq, addr, sizeof(h->groupAddrReq));
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    return error;
}


/* KeyBeacon_FloatingMaster
 * Switches h between being the floating master or just a client. */
int KeyBeacon_FloatingMaster(KeyBeacon_Handle_t* h, int fm)
{
    int error = 0;
    int locked = 0;

    if (h == NULL || h->state == KBS_invalid) {
        #if KEY_BEACON_LOGGING_LEVEL >= 1
            KB_PRINTF("KeyBeacon_FloatingMaster error: invalid parameter\n");
        #endif
        error = 1;
    }

    if (!error) {
        if (wc_LockMutex(&h->mutex) != 0) {
            #if KEY_BEACON_LOGGING_LEVEL >= 1
                KB_PRINTF("KeyBeacon_FloatingMaster error: couldn't lock mutex\n");
            #endif
            error = 1;
        }
        else
            locked = 1;
    }

    if (!error) {
        if (h->fmAllowed) {
            h->stateReq = (fm == KB_FM_RELEASE) ? KBS_client : KBS_master;
        }
        else {
            #if KEY_BEACON_LOGGING_LEVEL >= 1
                KB_PRINTF("KeyBeacon_FloatingMaster error: being master not allowed\n");
            #endif
            error = 1;
        }
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    return error;
}


/* KeyBeacon_Handler
 * Performs the actions of the Key Beacon. When being a server, it will
 * process WHO_IS_FM requests from other peers responding with I_AM_FM messages.
 * If the beacon is a client, it will ignore WHO_IS_FM messages, but will send
 * them if the application requests it. It also processes I_AM_FM messages.
 * This also performs all the requested settings changes. */
int KeyBeacon_Handler(KeyBeacon_Handle_t* h)
{
    int error = 0;
    int locked = 0;
    int sendMsg = 0;
    int recvd;
    char buf[2] = {0,0};
    struct in_addr addr;
    socklen_t addrSz;

    /* Read from the socket and wait for a packet. */
    recvd = KeySocket_RecvFrom(h->socket,
                               buf, sizeof(buf), 0,
                               (struct sockaddr*)&addr, &addrSz);

    if (recvd == WOLFSSL_CBIO_ERR_WANT_READ) {
        /* Try again later */
    }
    else if (recvd != 1) {
        /* Error */
        error = 1;
    }

    if (wc_LockMutex(&h->mutex) != 0) {
        KB_PRINTF("KeyBeacon_Handler error: couldn't lock mutex\n");
        error = 1;
    }
    else
        locked = 1;

    /* Update internal state accordingly. */
    if (!error) {
        if (h->fmAllowedReq != h->fmAllowed) {
            h->fmAllowed = h->fmAllowedReq;
            /* If the key beacon is current in master mode, and floating master
             * is being disallowed, request switch to client. */
            if (!h->fmAllowed && h->state == KBS_master)
                h->stateReq = KBS_client;
        }

        if (h->stateReq != h->state) {
            if (h->stateReq == KBS_client) {
                if (h->state == KBS_master) {
                    h->state = KBS_client;
                }
            }
            else {
                if (h->state != KBS_master) {
                    h->state = KBS_master;
                }
            }
        }

        if (h->socketReq != h->socket)
            h->socket = h->socketReq;

        if (h->portReq != h->port)
            h->port = h->portReq;

        if (memcmp(&h->groupAddr, &h->groupAddrReq,
                   sizeof(struct sockaddr)) != 0) {

            memcpy(&h->groupAddr, &h->groupAddrReq, sizeof(h->groupAddr));
        }
    }

    /* Respond as appropriate */
    if (!error) {
        if (h->state == KBS_master) {
            if ((int)buf[0] == KB_MSGID_WHOISFM) {
                buf[0] = KB_MSGID_IAMFM;
                sendMsg = 1;
            }
        }
        else if (h->state == KBS_client) {
            if (h->fmReq) {
                buf[0] = KB_MSGID_WHOISFM;
                sendMsg = 1;
            }
            if ((int)buf[0] == KB_MSGID_IAMFM) {
                h->fmReq = 0;
                h->fmKnown = 1;
            }
        }
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    if (sendMsg) {
        /* Send the packet. */
        KeySocket_SendTo(h->socket, buf, 1, 0,
                         &h->groupAddr, sizeof(h->groupAddr));
    }

    return error;
}


/* KeyBeacon_FindMaster
 * Tells the key beacon handler to find the current floating master. After a
 * call to this, KeyBeacon_GetMaster will return WAITING until the master
 * responds. If it returns success, there is a new master address available.
 * (Which could still be the old address.) */
int KeyBeacon_FindMaster(KeyBeacon_Handle_t* h)
{
    int error = 0;
    int locked = 0;

    if (h == NULL) {
        KB_PRINTF("KeyBeacon_FindMaster error: invalid parameter\n");
        error = 1;
    }

    if (!error) {
        if (wc_LockMutex(&h->mutex) != 0) {
            KB_PRINTF("KeyBeacon_FindMaster error: unable to lock mutex\n");
            error = 1;
        }
        else
            locked = 1;
    }

    if (!error) {
        h->fmKnown = 0;
        h->fmReq = 1;
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    return error;
}


/* KeyBeacon_GetMaster
 * Returns the address of the master in the parameter addr. If a master
 * lookup is in process, this function returns KB_FM_WAITING. If there
 * is an error, it returns KB_FM_FAILED. If the master address is copied
 * into addr, the function returns KB_FM_OK. */
int KeyBeacon_GetMaster(KeyBeacon_Handle_t *h, struct in_addr *addr)
{
    int error = KB_FM_OK;
    int locked = 0;

    if (h == NULL || addr == NULL) {
        KB_PRINTF("KeyBeacon_GetMaster error: invalid parameter\n");
        error = KB_FM_FAILED;
    }

    if (!error) {
        if (wc_LockMutex(&h->mutex) != 0) {
            KB_PRINTF("KeyBeacon_GetMaster error: unable to lock mutex\n");
            error = KB_FM_FAILED;
        }
        else
            locked = 1;
    }

    if (!error) {
        if (h->fmKnown) {
            memcpy(addr, &h->fmAddr, sizeof(struct in_addr));
        }
        else
            error = KB_FM_WAITING;
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    return error;
}
