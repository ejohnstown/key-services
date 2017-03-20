/* new-mcast-server.c */

/*
 gcc -Wall new-mcast-server.c -o ./new-mcast-server -lpthread

 will send time msg every second to group
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <pthread.h>


#define GROUP_ADDR "226.0.0.3"
#define GROUP_PORT  12345
#define MSG_SIZE    80


int main(int argc, char** argv)
{
    int sockfd, on = 1;
    struct sockaddr_in sender;
    int sender_len = sizeof(sender);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&sender, 0, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_addr.s_addr = inet_addr(GROUP_ADDR);
    sender.sin_port = htons(GROUP_PORT);

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t)sizeof(on));
#endif

    for(;;) {
        char msg[80];
        time_t t = time(0);
        sprintf(msg, "time is %-24.24s", ctime(&t));
        printf("sending msg = %s\n", msg);
        size_t msg_len = strlen(msg) + 1;

        ssize_t n = sendto(sockfd, msg, msg_len, 0, (struct sockaddr*)&sender,
                           sender_len);
        if (n < 0)
            perror("sendto error");
        sleep(1);
    }

    return 0;
}
