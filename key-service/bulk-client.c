#include <pthread.h>
#include "key-client.h"
#include "key-server.h"


#define MAX_THREAD_COUNT 100
#define IP_ADDR_OFFSET 21


typedef struct ginfo_t {
    int stop;
    unsigned short keyEpoch;
    unsigned short switchEpoch;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
} ginfo_t;

typedef struct tinfo_t {
    int idx;
    struct sockaddr_in addr;
} tinfo_t;


static ginfo_t gInfo =
    {0, 0, 0, PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER};


static void KeyBcastCallback(CmdPacket_t* pkt)
{
    if (pkt && pkt->header.type == CMD_PKT_TYPE_KEY_CHG) {
        /* trigger key change */
        unsigned char* addr = pkt->msg.keyChgResp.ipaddr;

        printf("Key Change Server: %d.%d.%d.%d\n",
            addr[0], addr[1], addr[2], addr[3]);

        pthread_mutex_lock(&gInfo.mutex);
        gInfo.keyEpoch = pkt->msg.keyChgResp.epoch[0] << 8 |
                         pkt->msg.keyChgResp.epoch[1];
        pthread_cond_broadcast(&gInfo.cond);
        pthread_mutex_unlock(&gInfo.mutex);

    }
    if (pkt && pkt->header.type == CMD_PKT_TYPE_KEY_USE) {
        printf("Key Change Server: Switch!\n");

        pthread_mutex_lock(&gInfo.mutex);
        gInfo.switchEpoch = pkt->msg.epochResp.epoch[0] << 8 |
                            pkt->msg.epochResp.epoch[1];
        pthread_cond_broadcast(&gInfo.cond);
        pthread_mutex_unlock(&gInfo.mutex);
    }
}


static void* KeyClientWorker(void* arg)
{
    tinfo_t* tInfo = (tinfo_t*)arg;
    int i = 0;
    int fd, status;
    unsigned short check = 0;

    printf("1: Thread %d starting\n", tInfo->idx);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("5: thread %d socket fail\n", tInfo->idx);
        return NULL;
    }

    status = bind(fd, (struct sockaddr*)&tInfo->addr, sizeof(tInfo->addr));
    if (status != 0) {
        printf("6: thread %d bind fail\n", tInfo->idx);
        return NULL;
    }

    printf("7: thread %d fd = %d\n", tInfo->idx, fd);

    pthread_mutex_lock(&gInfo.mutex);
    while (!gInfo.stop) {

        while (!gInfo.stop &&
               gInfo.keyEpoch == check &&
               gInfo.switchEpoch == check) {

            pthread_cond_wait(&gInfo.cond, &gInfo.mutex);
        }

        if (gInfo.stop)
            break;

        check = gInfo.switchEpoch;

        printf("2: Thread %d iteration %d\n", tInfo->idx, i++);
    }

    pthread_mutex_unlock(&gInfo.mutex);

    close(fd);
    printf("3: Thread %d ending\n", tInfo->idx);

    return NULL;
}


int main(int argc, char* argv[])
{
    tinfo_t blInfo; /* Broadcast listener thread info */
    pthread_t *kcPids; /* Key Client thread PIDs */
    tinfo_t *kcInfos; /* Key Client thread infos */
    tinfo_t *ti;
    pthread_t *pid;
    int status, i, tCount, ret;
    char ipAddr[16] = "127.0.0.1";

    kcPids = NULL;
    kcInfos = NULL;
    ret = 1;

    if (argc < 2) {
        printf("need the thread count\n");
        goto exit;
    }

    tCount = atoi(argv[1]);
    if (tCount < 1 || tCount > MAX_THREAD_COUNT) {
        printf("invalid thread count [1..%u]\n", MAX_THREAD_COUNT);
        goto exit;
    }

    kcPids = (pthread_t*)malloc(sizeof(pthread_t) * tCount);
    if (kcPids == NULL) {
        printf("cannot allocate the pids array\n");
        goto exit;
    }

    kcInfos = (tinfo_t*)malloc(sizeof(tinfo_t) * tCount);
    if (kcInfos == NULL) {
        printf("cannot allocate the thread infos array\n");
        goto exit;
    }

    status = pthread_mutex_init(&gInfo.mutex, NULL);
    if (status != 0) {
        printf("cannot init mutex\n");
        goto exit;
    }

    status = pthread_cond_init(&gInfo.cond, NULL);
    if (status != 0) {
        printf("cannot init cond\n");
        goto exit;
    }

    /* Start the broadcast listener thread. */
    blInfo.idx = -1;
    /*strcpy(ipAddr, "192.168.20.1");*/
    inet_pton(AF_INET, ipAddr, &blInfo.addr.sin_addr);
    blInfo.addr.sin_port = 0;

    /* Start the key client threads. */
    for (i = 0, pid = kcPids, ti = kcInfos;
         i < tCount;
         i++, pid++, ti++) {

        ti->idx = i;
        /*sprintf(ipAddr, "192.168.20.%d", IP_ADDR_OFFSET + i);*/
        inet_pton(AF_INET, ipAddr, &ti->addr.sin_addr);
        ti->addr.sin_port = 0;

        status = pthread_create(pid, NULL, KeyClientWorker, ti);
        if (status != 0)
            printf("0: thread %d failed (%d)\n", i, status);
    }

    status = KeyBcast_RunUdp(&blInfo.addr.sin_addr, KeyBcastCallback, NULL);
    if (status != 0) {
        printf("KeyBcast failed\n");
        goto exit;
    }

    pthread_mutex_lock(&gInfo.mutex);
    gInfo.stop = 1;
    pthread_cond_broadcast(&gInfo.cond);
    pthread_mutex_unlock(&gInfo.mutex);

    for (i = 0, pid = kcPids, ti = kcInfos;
         i < tCount;
         i++, pid++, ti++) {

        pthread_join(*pid, NULL);
    }

    ret = 0;

exit:
    pthread_cond_destroy(&gInfo.cond);
    pthread_mutex_destroy(&gInfo.mutex);
    free(kcInfos);
    free(kcPids);

    return ret;
}
