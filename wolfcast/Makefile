LIB_PATH=/usr/local
CFLAGS=-Wall -I$(LIB_PATH)/include -I. -I../key-service
LDFLAGS=-lpthread

# IP Addresses
CFLAGS+=-DLOCAL_ADDR=\"192.168.20.1\" -DKEY_SERV_LOCAL_ADDR="192,168,20.1" -DKEY_BCAST_ADDR="192,168,20,255"
CFLAGS+=-DWOLFCAST_LOGGING_LEVEL=3
CFLAGS+=-DKEY_SERVICE_LOGGING_LEVEL=3
CFLAGS+=-DKEY_SOCKET_LOGGING_LEVEL=3

# Dynamic wolfSSL library
LDFLAGS+=-lwolfssl -lm -L$(LIB_PATH)/lib

# Static wolfSSL library with Debug
#CFLAGS+=-g3 -DDEBUG
#LDFLAGS+=$(LIB_PATH)/lib/libwolfssl.a

# Building wolfSSL
#./configure --enable-psk --enable-mcast --enable-nullcipher CFLAGS="-DWOLFSSL_STATIC_PSK"
# Build wolfSSL with Debug add --enable-debug --disable-shared


all: wolfcast

key-socket.o: ../key-service/key-socket.c ../key-service/key-socket.h

key-services.o: ../key-service/key-services.c ../key-service/key-services.h ../key-service/key-socket.h

wolfcast.o: wolfcast.c wolfcast.h

wolfcast: wolfcast.o ../key-service/key-socket.o ../key-service/key-services.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o ../key-service/*.o wolfcast

.PHONY: clean all
