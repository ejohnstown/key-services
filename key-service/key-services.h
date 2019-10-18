#ifndef _KEY_SERVICES_H_
#define _KEY_SERVICES_H_

#include <stdint.h>

#define PMS_SIZE	   64 /* SHA256 Block size */
#define RAND_SIZE	   32
#define MAX_PACKET_MSG (sizeof(CmdMsg_t))
#define LISTENQ		   100*100	 /* maximum backlog queue items */
#define EPOCH_SIZE	   2
#define SUITE_SIZE	   2
#define CIPHER_SUITE_0 0
#define CIPHER_SUITE_1 0xFE
#define MAX_ID_LEN	   32 /* wolf supports up to 128 bytes */


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
	CMD_PKT_TYPE_KEY_CHG =	1, /* key server key has changed */
	CMD_PKT_TYPE_KEY_USE =	2, /* peers should use new key */
	CMD_PKT_TYPE_KEY_REQ =	3, /* get key from server */
	CMD_PKT_TYPE_KEY_NEW =	4, /* request server generate new key */

	CMD_PKT_TYPE_COUNT,
};

/* Key Response Packet */
typedef struct KeyRespPacket {
	unsigned char epoch[EPOCH_SIZE];
	unsigned char pms[PMS_SIZE];
	unsigned char serverRandom[RAND_SIZE];
	unsigned char clientRandom[RAND_SIZE];
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

typedef struct EpochAddrRespPacket {
	unsigned char ipaddr[4];
	unsigned char epoch[EPOCH_SIZE];
} WOLFSSL_PACK EpochAddrRespPacket_t;

/* Command Header */
typedef struct CmdHeader {
	unsigned char version; /* Version = 1 - Allows future protocol changes */
	unsigned char type;    /* Type: 0=Discovery, 1=KeyChg, 2=KeyReq, ...Future Commands */
	unsigned char id;	   /* Peer ID: 0-255 */
	unsigned char size[2]; /* Message Size (remaining packet bytes to follow) */
} WOLFSSL_PACK CmdHeader_t;

typedef union CmdMsg {
	unsigned char	  raw[0];

	/* public responses */
	EpochAddrRespPacket_t  keyChgResp;
	AddrRespPacket_t	   discResp;
	EpochRespPacket_t	   epochResp;

	/* private responses */
	KeyRespPacket_t		   keyResp;
} WOLFSSL_PACK CmdMsg_t;

/* Command Packet */
typedef struct CmdPacket {
	CmdHeader_t header;
	CmdMsg_t	msg;
} WOLFSSL_PACK CmdPacket_t;


/* PSK Client Identity */
/* Note: this is OpenSSL openssl s_client default, but can/should be customized */
#define CLIENT_IDENTITY  "Client_identity"

/* PSK Server Idenitity */
#define SERVER_IDENTITY  "wolfssl server"

/* PSK Cipher Suite */
#define PSK_CIPHER_SUITE "PSK-AES128-CBC-SHA256"

// Hack to allow change of TLS key for demonstration of authentication failure
/* PSK - Shared Key */
extern char tls_pre_shared_key[41];
extern uint32 tls_pre_shared_key_length;

#endif /* _KEY_SERVICES_H_ */
