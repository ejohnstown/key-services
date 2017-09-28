#ifndef _KEY_SERVER_H_
#define _KEY_SERVER_H_

#include "key-services.h"
#include "key-socket.h"

/* API's */
int KeyServer_Init(void* heap, const struct in_addr* srvAddr,
    unsigned short keyBcastPort, unsigned short keyServPort);
typedef void (*KeyServerReqPktCb)(CmdPacket_t* pkt);
int KeyServer_Run(KeyServerReqPktCb reqCb, void* heap);
int KeyServer_IsRunning(void);
void KeyServer_Pause(void);
void KeyServer_Resume(void);
void KeyServer_Stop(void);
int KeyServer_GenNewKey(void* heap);
int KeyServer_SetKeyResp(KeyRespPacket_t* keyRespPkt, void* heap);
int KeyServer_SetNewKey(unsigned short epoch,
    unsigned char* pms, int pmsSz,
    unsigned char* serverRandom, int serverRandomSz,
    unsigned char* clientRandom, int clientRandomSz, void* heap);
int KeyServer_NewKeyUse(void* heap);
int KeyServer_NewKeyChange(void* heap);
void KeyServer_Free(void* heap);
unsigned int KeyServer_GetAuthFailCount(void);

#endif
