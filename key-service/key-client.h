#ifndef _KEY_CLIENT_H_
#define _KEY_CLIENT_H_

#include "key-services.h"
#include "key-socket.h"

/* API's */
void KeyServices_Init(unsigned char peerId, unsigned short mcastPort, unsigned short servPort);

int KeyClient_Get(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);
int KeyClient_GetUdp(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);

int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap);
int KeyClient_GetKey_ex(const struct in_addr* srvAddr, const struct in_addr* cliAddr, KeyRespPacket_t* keyResp, void* heap);
int KeyClient_FindMaster(struct in_addr* srvAddr, void* heap);
int KeyClient_NewKeyRequest(const struct in_addr* srvAddr, EpochRespPacket_t* epochResp, void* heap);

/* Un-secure UDP multicast listening service */
typedef void (*KeyMcastReqPktCb)(CmdPacket_t* pkt);
int KeyMcast_RunUdp(const struct in_addr* srvAddr, KeyMcastReqPktCb respCb, void* heap);

void KeyMcast_DefaultCb(CmdPacket_t* pkt);

#endif
