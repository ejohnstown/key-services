/* new-mcast-client.c */

/*
 gcc -Wall new-mcast-client.c -o ./new-mcast-client -lpthread

 run different clients on different hosts to see client sends,
 this is because we're disabling MULTICAST_LOOP so that we don't have to
 process messages we send ourselves

 could run ./new-mcast-server on host 1 (this sends out a time msg every second)
 then run  ./new-mcast-client on host 1 (will see server time msgs)
 then      ./new-mcast-client on host 2 (will see server and client 1msgs, and
                                         host1 will see host2 msgs as well)

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


void* SendMsgThread(void* arg)
{
    int sfd, ret;
    struct sockaddr_in sender;
    int sender_len = sizeof(sender);

    int on  = 1;
    int off = 0;

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&sender, 0, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_addr.s_addr = inet_addr(GROUP_ADDR);
    sender.sin_port = htons(GROUP_PORT);

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t)sizeof(on));
#endif


    /* don't send to self */
    ret = setsockopt(sfd, IPPROTO_IP, IP_MULTICAST_LOOP,
                     &off, sizeof(off));
    if (ret < 0) {
        perror("setsockopt multicast loop off failed");
        exit(EXIT_FAILURE);
    }


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

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&receive, 0, sizeof(receive));
    receive.sin_family = AF_INET;
    receive.sin_addr.s_addr = htonl(INADDR_ANY);  /* don't bind to multi addr */
    receive.sin_port = htons(GROUP_PORT);

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t)sizeof(on));
#endif


    ret = bind(sockfd, (struct sockaddr*)&receive, sizeof(receive));
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }


    struct ip_mreq imreq;
    memset(&imreq, 0, sizeof(imreq));

    imreq.imr_multiaddr.s_addr = inet_addr(GROUP_ADDR);
    imreq.imr_interface.s_addr = INADDR_ANY;

    ret = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                     (const void*)&imreq, sizeof(imreq));
    if (ret < 0) {
        perror("setsockopt mc add membership failed");
        exit(EXIT_FAILURE);
    }


    pthread_t tid;
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
