LIB_PATH=/usr/local
CFLAGS=-Wall -I$(LIB_PATH)/include -I../wolfcast -DKEY_SERVER_LOCAL_IP="192,168,2,1"
DEBUG_CFLAGS=
NETX_CFLAGS=

# Dynamic wolfSSL library
LIBS=-lwolfssl -lm -L$(LIB_PATH)/lib

# Static wolfSSL library with Debug
# Build wolfSSL with Debug
#./configure --enable-debug --disable-shared
DEBUG_CFLAGS+=-g -DDEBUG
#LIBS=$(LIB_PATH)/lib/libwolfssl.a


# Enable NetX Networking
NETX_PATH=./NetX/ver5.5_sp1
THREADX_PATH=./ThreadX/ver5.6
#NETX_CFLAGS+=-DHAVE_NETX -I$(NETX_PATH) -I$(THREADX_PATH) -I$(THREADX_PATH)/Cortex_M3_M4/GCC

# Building wolfSSL
#./configure --enable-psk --enable-aesgcm CFLAGS="-DWOLFSSL_STATIC_PSK -DWOLFSSL_USER_IO" --enable-dtls --enable-mcast --enable-nullcipher


CFLAGS+=$(NETX_CFLAGS) $(DEBUG_CFLAGS)

all: mcastpeer key-client key-server

mcastpeer: mcastpeer.o key-services.o key-socket.o key-beacon.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

key-client: key-client.o key-services.o key-socket.o key-beacon.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

key-server: key-server.o key-services.o key-socket.o key-beacon.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o key-client key-server mcastpeer
