# TLS-PSK Key Client/Server

## Overview

The purpose of this project is to provide a way for devices to acquire their Pre-Master-Secret for Multicast DTLS. When a device comes online one is elected master and made the Key Server. The remainder become Key Clients and connect to the master to acquire the PMS.

The PMS will be randomly generated on server startup. The size of the PMS is 48 bytes (2 byte header and 46 RNG bytes).

## Protocol

The packed structures for command / response packets:

```
#define PMS_SIZE       64
#define RAND_SIZE      32
#define MAX_PACKET_MSG (PMS_SIZE + (RAND_SIZE * 2))

/* Command Header */
typedef struct CmdPacketHeader {
    uint8_t  version; /* Version = 1 - Allows future protocol changes */
    uint8_t  type;    /* Type: 1=KeyReq, 2=Future Commands */
    uint16_t size;    /* Message Size (remaining packet bytes to follow) */
} WOLFSSL_PACK CmdPacketHeader_t;

/* Command Request Packet */
typedef struct CmdReqPacket {
    struct CmdPacketHeader header;
} WOLFSSL_PACK CmdReqPacket_t;

/* Command Response Packet */
typedef struct CmdRespPacket {
    struct CmdPacketHeader header;
    union {
        uint8_t msg[MAX_PACKET_MSG];
        KeyRespPacket_t keyResp;
    }
} WOLFSSL_PACK CmdRespPacket_t;

typedef struct KeyRespPacket {
    uint8_t pms[PMS_SIZE];
    uint8_t serverRandom[RAND_SIZE];
    uint8_t clientRandom[RAND_SIZE];
} WOLFSSL_PACK KeyRespPacket_t;
```

## API's

The interfaces for server and client:

```
/* Run the key server to present clients PMS data. Is blocking. */
int KeyServer_Run(void* heap);
int KeyServer_IsRunning(void);
void KeyServer_Stop(void);

/* Performs TLS PSK operation against provided server IP to get key info. If the server is running locally then it will be retrieved from memory */
int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap);

/* Submit a custom request to server */
int KeyClient_Get(const struct in_addr* srvAddr, int reqType, uint8_t* msg, int* msgLen, void* heap);
```

## Building wolfSSL

```
./configure --enable-psk --enable-aesgcm CFLAGS="-DWOLFSSL_STATIC_PSK -DWOLFSSL_USER_IO" --enable-dtls --enable-mcast --enable-nullcipher
make
sudo make install
```

### Enabling Debugging

Build wolfSSL with debugging enabled. This will compile and install a static library.
```
./configure --enable-psk --enable-aesgcm CFLAGS="-DWOLFSSL_STATIC_PSK -DWOLFSSL_USER_IO" --enable-dtls --enable-mcast --enable-nullcipher --enable-debug --disable-shared
make
sudo make install
```

Edit the Makefile:
Un-comment the following lines:

```
LIBS=/usr/local/lib/libwolfssl.a
CFLAGS+=-g -DDEBUG
```

And comment out:

```
#LIBS=-lwolfssl -lm -L/usr/local/lib
```

## Usage


Teriminal 1:

```
./key-server 

Connection from 127.0.0.1, port 60989
Request: Version 1, Cmd 1, Size 0
```

Terminal 2:

```
./key-client 127.0.0.1

Response: Version 1, Cmd 1, Size 128
```


## Testing

### DTLS Multicast Peer Test Tool

This test tool creates threads simulating multiple peers. The default configuration sends a status every 20ms (50Hz).

#### Usage

The ./mcastpeer [threads] tool starts a key-service thread, then spawn up as many peer threads as incidated. It will first get the key from the key-server then start sending status at 50hz and reading in-between. Tracks elapsed time and rx/tx counts, which are displayed on termination with Ctrl+C.

```
./mcastpeer 
Usage: mcastpeer [threads]
```

#### Example output

```
./mcastpeer 2
Connection from 127.0.0.1, port 54182
Request: Version 1, Cmd 1, Size 0
Response: Version 1, Cmd 1, Size 128
Connection from 127.0.0.1, port 54183
Request: Version 1, Cmd 1, Size 0
Response: Version 1, Cmd 1, Size 128
^C
Stopping peers
Peer 0: Ret 0, Elapsed 1701 ms, TX 74, RX 148
Peer 1: Ret 0, Elapsed 1700 ms, TX 74, RX 147
```
