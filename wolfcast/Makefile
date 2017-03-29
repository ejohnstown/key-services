CFLAGS=-I. -I../key-service
LDFLAGS=-lwolfssl
CPPFLAGS=-DKEY_ADDR=\"192.168.2.1\" -DLOCAL_ADDR=\"192.168.2.1\" -DKEY_SERVER_LOCAL_IP="192,168,2,1"

all: wolfcast

key-socket.o: ../key-service/key-socket.c ../key-service/key-socket.h

key-services.o: ../key-service/key-services.c ../key-service/key-services.h ../key-service/key-socket.h

key-beacon.o: ../key-service/key-beacon.c ../key-service/key-beacon.h

wolfcast.o: wolfcast.c wolfcast.h

wolfcast: wolfcast.o ../key-service/key-socket.o ../key-service/key-services.o ../key-service/key-beacon.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o ../key-service/*.o wolfcast

.PHONY: clean all
