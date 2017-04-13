CFLAGS=-I. -I../key-service -g3 -DDEBUG
LDFLAGS=-lwolfssl
CPPFLAGS=-DLOCAL_ADDR=\"192.168.0.112\" -DKEY_SERV_LOCAL_ADDR="192,168,0,112" -DKEY_BCAST_ADDR="192,168,0,255"

all: wolfcast

key-socket.o: ../key-service/key-socket.c ../key-service/key-socket.h

key-services.o: ../key-service/key-services.c ../key-service/key-services.h ../key-service/key-socket.h

wolfcast.o: wolfcast.c wolfcast.h

wolfcast: wolfcast.o ../key-service/key-socket.o ../key-service/key-services.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o ../key-service/*.o wolfcast

.PHONY: clean all
