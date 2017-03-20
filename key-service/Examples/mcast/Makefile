all: server client client1 client2 client3

server: wolfserver.c
	gcc -Wall wolfserver.c -o ./server -lwolfssl

client: wolfclient.c
	gcc -Wall wolfclient.c -o ./client -lwolfssl

client1: wolfclient1.c
	gcc -Wall wolfclient1.c -o ./client1 -lwolfssl

client2: wolfclient2.c
	gcc -Wall wolfclient2.c -o ./client2 -lwolfssl

client3: wolfclient3.c
	gcc -Wall wolfclient3.c -o ./client3 -lwolfssl

clean:
	rm -rf server client client1 client2 client3

.PHONY: clean all
