#ifndef _KEY_SERVICE_H_
#define _KEY_SERVICE_H_

#include <stdint.h>
#include "key-socket.h"

#define PMS_SIZE       64 /* SHA256 Block size */
#define RAND_SIZE      32
#define MAX_PACKET_MSG (sizeof(CmdMsg_t))
#define LISTENQ        100*100   /* maximum backlog queue items */
#define EPOCH_SIZE     2
#define SUITE_SIZE     2
#define CIPHER_SUITE_0 0
#define CIPHER_SUITE_1 0xFE
#define MAX_ID_LEN     32 /* wolf supports up to 128 bytes */

/* Subnet to broadcast key discovery message */
#ifndef KEY_BCAST_ADDR
    #error Please define KEY_BCAST_ADDR with comma notation
#endif
#ifndef KEY_BCAST_PORT
    #define KEY_BCAST_PORT      22222
#endif

/* IP address to return for key server discovery */
#ifndef KEY_SERV_LOCAL_ADDR
    #error Please define KEY_SERV_LOCAL_ADDR with comma notation
#endif
#ifndef KEY_SERV_PORT
    #define KEY_SERV_PORT       11111
#endif


#ifdef HAVE_NETX
    #define KEY_SERVICE_SLEEP(x) tx_thread_sleep(x)
    #define KEY_SERVICE_TICKS_PER_SECOND 100
#else
    #define KEY_SERVICE_SLEEP(x) usleep(x)
    #define KEY_SERVICE_TICKS_PER_SECOND 1000000
#endif


#ifndef WOLFSSL_PACK
#if defined(__GNUC__)
    #define WOLFSSL_PACK __attribute__ ((packed))
#else
    #define WOLFSSL_PACK
#endif
#endif

/* Command Packet Version */
#define CMD_PKT_VERSION 0x01

/* Command Packet Types */
enum CmdPacketCommandType {
    CMD_PKT_TYPE_INVALID = -1,
    CMD_PKT_TYPE_DISCOVER = 0, /* find key servers */
    CMD_PKT_TYPE_KEY_CHG =  1, /* key server key has changed */
    CMD_PKT_TYPE_KEY_USE =  2, /* peers should use new key */
    CMD_PKT_TYPE_KEY_REQ =  3, /* get key from server */
    CMD_PKT_TYPE_KEY_NEW =  4, /* request server generate new key */

    CMD_PKT_TYPE_COUNT,
};

/* Key Response Packet */
typedef struct KeyRespPacket {
    unsigned char epoch[EPOCH_SIZE];
    unsigned char pms[PMS_SIZE];
    unsigned char serverRandom[3][RAND_SIZE];
    unsigned char clientRandom[3][RAND_SIZE];
    unsigned char suite[SUITE_SIZE];
} WOLFSSL_PACK KeyRespPacket_t;

/* Key Change and Discovery response packet */
typedef struct AddrRespPacket {
    unsigned char ipaddr[4];
} WOLFSSL_PACK AddrRespPacket_t;

/* Use New Key response packet */
typedef struct EpochRespPacket {
    unsigned char epoch[EPOCH_SIZE];
} WOLFSSL_PACK EpochRespPacket_t;

/* Command Header */
typedef struct CmdHeader {
    unsigned char version; /* Version = 1 - Allows future protocol changes */
    unsigned char type;    /* Type: 0=Discovery, 1=KeyChg, 2=KeyReq, ...Future Commands */
    unsigned char id;      /* Peer ID: 0-255 */
    unsigned char size[2]; /* Message Size (remaining packet bytes to follow) */
} WOLFSSL_PACK CmdHeader_t;

typedef union CmdMsg {
    unsigned char     raw[0];

    /* public responses */
    AddrRespPacket_t  keyChgResp;
    AddrRespPacket_t  discResp;
    EpochRespPacket_t epochResp;

    /* private responses */
    KeyRespPacket_t   keyResp;
} WOLFSSL_PACK CmdMsg_t;

/* Command Packet */
typedef struct CmdPacket {
    CmdHeader_t header;
    CmdMsg_t    msg;
} WOLFSSL_PACK CmdPacket_t;


/* PSK Client Identity */
/* Note: this is OpenSSL openssl s_client default, but can/should be customized */
#define CLIENT_IDENTITY  "Client_identity"

/* PSK Server Idenitity */
#define SERVER_IDENTITY  "wolfssl server"

/* PSK Cipher Suite */
#define PSK_CIPHER_SUITE "PSK-AES128-CBC-SHA256"

/* PSK - Shared Key */
static const unsigned char g_TlsPsk[4] = {
    0x01, 0x02, 0x03, 0x04
};


/* API's */
int KeyServer_Init(void* heap, const struct in_addr* srvAddr);
typedef void (*KeyServerReqPktCb)(CmdPacket_t* pkt);
int KeyServer_Run(KeyServerReqPktCb reqCb, void* heap);
int KeyServer_IsRunning(void);
void KeyServer_Pause(void);
void KeyServer_Resume(void);
void KeyServer_Stop(void);
int KeyServer_GenNewKey(void* heap);
int KeyServer_SetNewKey(unsigned char* pms, int pmsSz,
    unsigned char* serverRandom, int serverRandomSz,
    unsigned char* clientRandom, int clientRandomSz, void* heap);
int KeyServer_NewKeyUse(void* heap);
int KeyServer_NewKeyChange(void* heap);
void KeyServer_Free(void* heap);

int KeyClient_Get(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);
int KeyClient_GetUdp(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);

int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap);
int KeyClient_FindMaster(struct in_addr* srvAddr, void* heap);
int KeyClient_NewKeyRequest(const struct in_addr* srvAddr, EpochRespPacket_t* epochResp, void* heap);

/* Un-secure UDP broadcast listening service */
typedef void (*KeyBcastReqPktCb)(CmdPacket_t* pkt);
int KeyBcast_RunUdp(const struct in_addr* srvAddr, KeyBcastReqPktCb respCb, void* heap);

void KeyBcast_DefaultCb(CmdPacket_t* pkt);

#endif /* _KEY_SERVICE_H_ */
