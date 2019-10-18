#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "key-services.h"

#ifndef _WOLFLOCAL_H_
#define _WOLFLOCAL_H_

extern UCHAR *heap_address;
extern UINT heap_size;

unsigned int LowResTimer(void);


typedef struct wolfWrapper_t {
	WOLFSSL_CTX* ctx;
	WOLFSSL* curSsl;
	WOLFSSL* prevSsl;
	unsigned short prevEpoch;
	unsigned short epoch;
	KeyRespPacket_t keyState;
	UINT keySet;
	UINT switchKeys;
	const USHORT* peerIdList;
	UINT peerIdListSz;
	unsigned char myId;
	ULONG groupAddr;
	unsigned short groupPort;
	UINT macDropCount;
	UINT replayDropCount;
	UINT epochDropCount;
	NX_UDP_SOCKET realTxSocket;
	NX_UDP_SOCKET realRxSocket;
	NX_IP *ip;
	NX_PACKET_POOL *pool;
	NX_PACKET *rxPacket;
} wolfWrapper_t;

void WolfLocalInit(wolfWrapper_t*, UCHAR);
void WolfLocalTimer(void);
void WolfLocalRekey(void);
struct in_addr WolfLocalGetKeySrvAddr(void);

int wolfWrapper_Init(wolfWrapper_t*, UCHAR, USHORT, ULONG,
					 const USHORT*, UINT, void*, UINT);
int wolfWrapper_Write(wolfWrapper_t*, const void*, int);
void wolfWrapper_Read_Packet(wolfWrapper_t*, NX_PACKET*, USHORT*, void*, int, int*);
int wolfWrapper_Read(wolfWrapper_t*, USHORT*, void*, int);
int wolfWrapper_GetErrorStats(wolfWrapper_t*, unsigned int*,
							  unsigned int*, unsigned int*);

#endif
