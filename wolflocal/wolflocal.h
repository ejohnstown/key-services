#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "key-services.h"

#ifndef _WOLFLOCAL_H_
#define _WOLFLOCAL_H_

int mySeed(unsigned char*, unsigned int);
unsigned int LowResTimer(void);


void WolfLocalInit(void);
void WolfLocalTimer(void);


typedef struct wolfWrapper_t {
    UINT streamId;
    WOLFSSL_CTX* ctx;
    WOLFSSL* curSsl;
    WOLFSSL* prevSsl;
    unsigned short epoch;
    unsigned short newEpoch;
    KeyRespPacket_t keyState;
    UINT keySet;
    UINT switchKeys;
    const USHORT* peerIdList;
    UINT peerIdListSz;
    unsigned char myId;
    ULONG groupAddr;
    unsigned short groupPort;
    KS_SOCKET_T txSocket;
    KS_SOCKET_T rxSocket;
    NX_UDP_SOCKET realTxSocket;
    NX_UDP_SOCKET realRxSocket;
    NX_IP *ip;
    NX_PACKET_POOL *pool;
    NX_PACKET *rxPacket;
} wolfWrapper_t;


int wolfWrapper_Init(wolfWrapper_t*, UINT, UCHAR, USHORT, ULONG,
                     const USHORT*, UINT, void*, UINT);
int wolfWrapper_Update(wolfWrapper_t*);
int wolfWrapper_Write(wolfWrapper_t*, const void*, int);
int wolfWrapper_Read(wolfWrapper_t*, USHORT*, void*, int);
int wolfWrapper_GetErrorStats(wolfWrapper_t*, unsigned int*, unsigned int*);

#endif
