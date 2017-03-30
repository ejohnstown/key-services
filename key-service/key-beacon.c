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
    KeyBeacon_State_t state;
    int fmAllowed; /* This KeyBeacon is allowed to become floating master */
    int fmKnown; /* floating master location known */
    int fmReq;   /* request to find the master */
    struct in_addr fmAddr; /* floating master's address */
    struct in_addr myAddr; /* This peer's address */
    struct sockaddr groupAddr; /* key beacon group address */
    unsigned short port;
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
        h->fmAllowed = KB_FM_NOTALLOWED;
        h->socket = KS_SOCKET_T_INIT;
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
        h->fmAllowed = (allow == KB_FM_NOTALLOWED) ?
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
                        struct sockaddr* groupAddr, struct in_addr* myAddr)
{
    int error = 0;
    int locked = 0;

    if (h == NULL || socket == 0 || groupAddr == NULL || myAddr == NULL) {
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
        h->socket = socket;
        h->port = ((struct sockaddr_in*)groupAddr)->sin_port;
        memcpy(&h->groupAddr, groupAddr, sizeof(h->groupAddr));
        memcpy(&h->myAddr, myAddr, sizeof(h->myAddr));
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
        if (fm == KB_FM_RELEASE)
            h->state = KBS_client;
        else if (h->fmAllowed) {
            h->state = KBS_master;
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
    if (h->socket != KS_SOCKET_T_INIT) {
        recvd = KeySocket_RecvFrom(h->socket,
                                   buf, sizeof(buf), 0,
                                   (struct sockaddr*)&addr, &addrSz);
    }
    else
        recvd = WOLFSSL_CBIO_ERR_WANT_READ;

    if (recvd == WOLFSSL_CBIO_ERR_WANT_READ) {
        printf("Want read\n");
        /* Try again later */
    }
    else if (recvd != 1) {
        /* Error */
        printf("Read had hard failure\n");
        error = 1;
    }

    if (wc_LockMutex(&h->mutex) != 0) {
        KB_PRINTF("KeyBeacon_Handler error: couldn't lock mutex\n");
        error = 1;
    }
    else
        locked = 1;

    /* Respond as appropriate */
    if (!error) {
        if (h->state == KBS_master) {
            printf("State: master\n");
            if ((int)buf[0] == KB_MSGID_WHOISFM) {
                buf[0] = KB_MSGID_IAMFM;
                sendMsg = 1;
            }
        }
        else if (h->state == KBS_client) {
            printf("State: client\n");
            if (h->fmReq) {
                printf("Attempting to send WHOIS\n");
                buf[0] = KB_MSGID_WHOISFM;
                sendMsg = 1;
            }
            if ((int)buf[0] == KB_MSGID_IAMFM) {
                h->fmReq = 0;
                h->fmKnown = 1;
            }
        }
        else
            printf("Some other state\n");
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    if (sendMsg) {
        /* Send the packet. */
        printf("Sending message\n");
        recvd = KeySocket_SendTo(h->socket, buf, 1, 0,
                                 &h->groupAddr, sizeof(h->groupAddr));
        if (recvd <= 0) {
            error = 1;
            recvd = errno;
            printf("Message error %d\n", error);
        }
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
        if (h->state == KBS_master) {
            memcpy(addr, &h->myAddr, sizeof(h->myAddr));
        } else if (h->fmKnown) {
            memcpy(addr, &h->fmAddr, sizeof(h->fmAddr));
        }
        else
            error = KB_FM_WAITING;
    }

    if (locked)
        wc_UnLockMutex(&h->mutex);

    return error;
}
