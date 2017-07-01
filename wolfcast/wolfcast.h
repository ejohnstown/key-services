#ifndef _WOLFCAST_H_
#define _WOLFCAST_H_

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "wolflocal.h"

#ifndef NETX
    #include <arpa/inet.h>
    typedef struct SocketInfo_t {
        int txFd;
        int rxFd;
        unsigned short groupPort;
        struct sockaddr_in tx;
        unsigned int txSz;
        unsigned char *rxPacket;
        unsigned long rxPacketSz;
    } SocketInfo_t;
#else
    #include "nx_api.h"
    #ifdef PGB000
        #include "pgb000_com.h"
    #else /* PGB002 */
        #include "pgb002_ap2.h"
    #endif

    typedef struct SocketInfo_t {
        NX_IP *ip;
        NX_PACKET_POOL *pool;
        NX_UDP_SOCKET txSocket;
        NX_UDP_SOCKET rxSocket;
        ULONG ipAddr;
        UINT groupPort;
        NX_PACKET *rxPacket;
    } SocketInfo_t;
#endif

int WolfcastInit(int, unsigned short, unsigned short,
                 WOLFSSL_CTX **, SocketInfo_t *, unsigned char*, unsigned int);
int WolfcastSessionNew(WOLFSSL **, WOLFSSL_CTX *, SocketInfo_t *, int,
                   const unsigned short *, unsigned int);
int WolfcastClientInit(unsigned int *, unsigned int *);
int WolfcastClient(wolfWrapper_t*, unsigned int *, unsigned int *);
int WolfcastServer(WOLFSSL *);

#endif /* _WOLFCAST_H_ */
