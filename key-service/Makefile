LIB_PATH=/usr/local
CFLAGS=-Wall -I$(LIB_PATH)/include
LDFLAGS=

# IP Addresses
CFLAGS+=-DKEY_SERV_LOCAL_ADDR="192,168,20,1" -DKEY_BCAST_ADDR="192,168,20,255"
CFLAGS+=-DWOLFLOCAL_STATIC_MEMORY_SZ=80000

# Dynamic wolfSSL library
LDFLAGS+=-lwolfssl -lm -L$(LIB_PATH)/lib

# Static wolfSSL library with Debug
#CFLAGS+=-g3 -DDEBUG
#LDFLAGS+=$(LIB_PATH)/lib/libwolfssl.a

# Building wolfSSL
#./configure --enable-psk --enable-mcast --enable-nullcipher CFLAGS="-DWOLFSSL_STATIC_PSK"
# Build wolfSSL with Debug add --enable-debug --disable-shared

# Enable NetX Networking
NETX_PATH=./NetX/ver5.5_sp1
THREADX_PATH=./ThreadX/ver5.6
#CFLAGS+=-DHAVE_NETX -I$(NETX_PATH) -I$(THREADX_PATH) -I$(THREADX_PATH)/Cortex_M3_M4/GCC

# Building wolfSSL
#./configure --enable-psk --enable-mcast --enable-nullcipher CFLAGS="-DWOLFSSL_STATIC_PSK"
# Build wolfSSL with Debug add --enable-debug --disable-shared


all: mcastpeer key-client key-server

mcastpeer: mcastpeer.o key-services.o key-socket.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

key-client: key-client.o key-services.o key-socket.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

key-server: key-server.o key-services.o key-socket.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean all

clean:
	rm -f *.o key-client key-server mcastpeer
