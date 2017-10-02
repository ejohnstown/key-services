#ifndef _KEY_CLIENT_H_
#define _KEY_CLIENT_H_

#include "key-services.h"
#include "key-socket.h"

/* API's */
void KeyServices_Init(unsigned char peerId, unsigned short bcastPort, unsigned short servPort);

int KeyClient_Get(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);
int KeyClient_GetUdp(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);

int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap);
int KeyClient_FindMaster(struct in_addr* srvAddr, void* heap);
int KeyClient_NewKeyRequest(const struct in_addr* srvAddr, EpochRespPacket_t* epochResp, void* heap);

/* Un-secure UDP broadcast listening service */
typedef void (*KeyBcastReqPktCb)(CmdPacket_t* pkt);
int KeyBcast_RunUdp(const struct in_addr* srvAddr, KeyBcastReqPktCb respCb, void* heap);

void KeyBcast_DefaultCb(CmdPacket_t* pkt);

#endif
