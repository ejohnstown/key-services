CFLAGS=-I. -I../key-service
LDFLAGS=-lwolfssl

all: wolfcast

key-socket.o: ../key-service/key-socket.c ../key-service/key-socket.h

key-services.o: ../key-service/key-services.c ../key-service/key-services.h ../key-service/key-socket.h

wolfcast.o: wolfcast.c wolfcast.h

wolfcast: wolfcast.o ../key-service/key-socket.o ../key-service/key-services.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o wolfcast

.PHONY: clean all
