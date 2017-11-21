#include <pthread.h>
#include "key-client.h"
#include "key-server.h"


#define MAX_THREAD_COUNT 100
#define IP_ADDR_OFFSET 21
const char gNetworkBase[] = "192.168.20";


typedef struct ginfo_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    /* Get mutex. */
    int stop;
    unsigned short keyEpoch;
    unsigned short switchEpoch;
    int mcastTrigger;
    int mcastFd;

    /* Read only. */
    struct sockaddr_in srvAddr;
} ginfo_t;

typedef struct tinfo_t {
    int idx;
    struct sockaddr_in addr;
} tinfo_t;


static ginfo_t gInfo =
    {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0, 0};


static void *TimerWorker(void* arg)
{
    useconds_t timeout = (unsigned int)arg * 1000;
    int stop;

    do {
        /*printf("Sleeping for %ums.\n", (unsigned int)arg);*/
        usleep(timeout);
        pthread_mutex_lock(&gInfo.mutex);
        gInfo.mcastTrigger++;
        stop = gInfo.stop;
        pthread_cond_broadcast(&gInfo.cond);
        pthread_mutex_unlock(&gInfo.mutex);
    } while (!stop);

    return NULL;
}


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
        memcpy(&gInfo.srvAddr.sin_addr.s_addr, addr,
               sizeof(gInfo.srvAddr.sin_addr.s_addr));
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
    int stop = 0, mcastTrigger, newMcastTrigger, status;
    unsigned short keyEpoch, newKeyEpoch, switchEpoch, newSwitchEpoch;
    KeyRespPacket_t keyResp;

    keyEpoch = newKeyEpoch = switchEpoch = newSwitchEpoch = 0;
    mcastTrigger = newMcastTrigger = 0;

#ifdef LOGGING
    printf("1: Thread %d starting\n", tInfo->idx);
#endif

    KeyServices_Init(tInfo->idx, 22222, 11111);

    while (!stop) {
        pthread_mutex_lock(&gInfo.mutex);
        while (!gInfo.stop &&
               gInfo.keyEpoch == keyEpoch &&
               gInfo.switchEpoch == switchEpoch &&
               gInfo.mcastTrigger == mcastTrigger) {

            pthread_cond_wait(&gInfo.cond, &gInfo.mutex);
        }
        stop = gInfo.stop;
        newKeyEpoch = gInfo.keyEpoch;
        newSwitchEpoch = gInfo.switchEpoch;
        newMcastTrigger = gInfo.mcastTrigger;
        pthread_mutex_unlock(&gInfo.mutex);

        if (stop)
            break;

        if (newKeyEpoch != keyEpoch) {
            /* Get the new key. If successful, update keyEpoch. */
#ifdef LOGGING
            printf("10: Thread %d getting epoch %hu\n", tInfo->idx, newKeyEpoch);
#endif
            status = KeyClient_GetKey_ex(&gInfo.srvAddr.sin_addr,
                                         &tInfo->addr.sin_addr,
                                         &keyResp, NULL);
            if (status == 0) {
                unsigned short respEpoch = (keyResp.epoch[0] << 8 | keyResp.epoch[1]);
                if (newKeyEpoch == respEpoch) {
#ifdef LOGGING
                    printf("11: Thread %d got epoch %hu\n", tInfo->idx, newKeyEpoch);
#endif
                    keyEpoch = newKeyEpoch;
                }
            }
            else {
#ifdef LOGGING
                printf("13: Thread %d couldn't get key, will try again later.\n", tInfo->idx);
#endif
            }
        }

        if (newSwitchEpoch != switchEpoch) {
            /* If the switch key is the same as our current keyEpoch,
             * switch over. */
            if (newSwitchEpoch == keyEpoch)  {
#ifdef LOGGING
                printf("12: Thread %d switching to epoch %hu\n", tInfo->idx, newSwitchEpoch);
#endif
                switchEpoch = newSwitchEpoch;
            }
        }

        if (newMcastTrigger != mcastTrigger) {
            unsigned char buffer[6] = {0, 4, 8, 16, 23, 42};
            int sent;

            mcastTrigger = newMcastTrigger;
            /*printf("Thread %d, wakey wakey! (%d)\n", tInfo->idx, mcastTrigger);*/

            buffer[0] = tInfo->idx;
            sent = (int)sendto(gInfo.mcastFd, buffer, sizeof(buffer), 0,
                    (struct sockaddr*)&gInfo.srvAddr, sizeof(gInfo.srvAddr));
            if (sent != sizeof(buffer))
                printf("couldn't send data\n");
        }
    }

#ifdef LOGGING
    printf("3: Thread %d ending\n", tInfo->idx);
#endif

    return NULL;
}


int main(int argc, char* argv[])
{
    tinfo_t blInfo; /* Broadcast listener thread info */
    pthread_t *kcPids; /* Key Client thread PIDs */
    tinfo_t *kcInfos; /* Key Client thread infos */
    tinfo_t *ti;
    pthread_t *pid;
    pthread_t timerPid;
    int status, i, tCount, ret;
    int on = 1;
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

    /* Set up the broadcast listener address. */
    blInfo.idx = -1;
    sprintf(ipAddr, "%s.2", gNetworkBase);
    inet_pton(AF_INET, ipAddr, &blInfo.addr.sin_addr);
    blInfo.addr.sin_family = AF_INET;
    blInfo.addr.sin_port = 0;

    /* Make the mcast socket. */
    gInfo.mcastFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (gInfo.mcastFd < 0) {
        printf("5: mcastFd socket fail\n");
        goto exit;
    }

    status = setsockopt(gInfo.mcastFd,
                        SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (status < 0)
        goto exit;
#ifdef SO_REUSEPORT
    status = setsockopt(gInfo.mcastFd,
                        SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    if (status < 0)
        goto exit;
#endif

    status = bind(gInfo.mcastFd,
                  (struct sockaddr*)&blInfo.addr, sizeof(blInfo.addr));
    if (status != 0) {
        int err = errno;
        printf("6: mcastFd socket bind fail: %s\n", strerror(err));
        goto exit;
    }

    memset(&gInfo.srvAddr, 0, sizeof(gInfo.srvAddr));
    sprintf(ipAddr, "%s.1", gNetworkBase);
    inet_pton(AF_INET, ipAddr, &gInfo.srvAddr.sin_addr);
    gInfo.srvAddr.sin_family = AF_INET;
    gInfo.srvAddr.sin_port = htons(12345);

    /* This is the init for the local key broadcast listener. It should
     * be using a different peer ID than any of the key clients or the
     * key server. */
    KeyServices_Init(102, 22222, 11111);

    /* Start the key client threads. */
    for (i = 0, pid = kcPids, ti = kcInfos;
         i < tCount;
         i++, pid++, ti++) {

        ti->idx = i;
        sprintf(ipAddr, "%s.%d", gNetworkBase, IP_ADDR_OFFSET + i);
        ti->addr.sin_family = AF_INET;
        inet_pton(AF_INET, ipAddr, &ti->addr.sin_addr);
        ti->addr.sin_port = 0;

        status = pthread_create(pid, NULL, KeyClientWorker, ti);
#ifdef LOGGING
        if (status != 0)
            printf("0: thread %d failed (%d)\n", i, status);
#endif
    }

    status = pthread_create(&timerPid, NULL, TimerWorker, (void*)750);
#ifdef LOGGING
    if (status != 0)
        printf("0: thread TIMER failed (%d)\n", status);
#endif

    status = KeyBcast_RunUdp(&blInfo.addr.sin_addr, KeyBcastCallback, NULL);
    if (status != 0) {
        printf("KeyBcast failed %d\n", status);
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
    pthread_join(timerPid, NULL);

    ret = 0;

exit:
    pthread_cond_destroy(&gInfo.cond);
    pthread_mutex_destroy(&gInfo.mutex);
    close(gInfo.mcastFd);
    free(kcInfos);
    free(kcPids);

    return ret;
}
