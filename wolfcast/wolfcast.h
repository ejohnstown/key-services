#ifndef _WOLFCAST_H_
#define _WOLFCAST_H_

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#ifndef NETX
    #include <arpa/inet.h>
    typedef struct SocketInfo_t {
        int txFd;
        int rxFd;
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
        UINT port;
        NX_PACKET *rxPacket;
    } SocketInfo_t;
#endif

int WolfcastInit(int, unsigned short, WOLFSSL_CTX **, SocketInfo_t *);
int WolfcastClientInit(unsigned int *, unsigned int *);
int WolfcastClient(SocketInfo_t *, WOLFSSL *, WOLFSSL *,
                   unsigned short, unsigned short,
                   unsigned int *, unsigned int *);
int WolfcastServer(WOLFSSL *);

#endif /* _WOLFCAST_H_ */