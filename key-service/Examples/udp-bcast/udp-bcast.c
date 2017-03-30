/* udp-bcast.c */

/*
 gcc -Wall udp-bcast.c -o ./udp-bcast -lpthread

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


#define BCAST_ADDR "192.168.0.255"
#define BCAST_PORT  11111
#define MSG_SIZE    80


void* SendMsgThread(void* arg)
{
    int sfd;
    struct sockaddr_in sender;
    int sender_len = sizeof(sender);

    int on  = 1;

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&sender, 0, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_addr.s_addr = inet_addr(BCAST_ADDR);
    sender.sin_port = htons(BCAST_PORT);

    setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &on, (socklen_t)sizeof(on));

    pid_t self = getpid();
    printf("pid %d about to start sending every 3 seconds\n", self);
    int i = 1;
    for(;;) {
        char msg[80];
        sprintf(msg, "%d sending message %d", self, i++);
        size_t msg_len = strlen(msg) + 1;
        ssize_t n = sendto(sfd, msg, msg_len, 0, (struct sockaddr*)&sender,
                           sender_len);
        if (n < 0) {
            perror("sendto sender failed");
        }
        sleep(3);
    }

    return NULL;
}


int main(int argc, char** argv)
{
    int sockfd, ret, on = 1;
    struct sockaddr_in receive;
    socklen_t receive_len = sizeof(receive);
    pthread_t tid;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&receive, 0, sizeof(receive));
    receive.sin_family = AF_INET;
    receive.sin_addr.s_addr = htonl(INADDR_ANY);  /* don't bind to multi addr */
    receive.sin_port = htons(BCAST_PORT);

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, (socklen_t)sizeof(on));

    ret = bind(sockfd, (struct sockaddr*)&receive, sizeof(receive));
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&tid, NULL, SendMsgThread, NULL) < 0) {
        perror("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    for(;;) {
        char msg[MSG_SIZE];

        ssize_t n = recvfrom(sockfd, msg, MSG_SIZE, 0,
                             (struct sockaddr*)&receive, &receive_len);
        if (n < 0)
            perror("recvfrom error");

        printf("got msg %s\n", msg);

    }

    return 0;
}
