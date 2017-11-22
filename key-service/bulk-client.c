/* bulk-client.c
 *
 * $ bulk-client nclients
 *    nclients - number of clients to run
 */

#include <pthread.h>
#include "key-client.h"
#include "key-server.h"


#define LOGGING_LEVEL 2

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#ifndef LOGGING_LEVEL
    #define LOGGING_LEVEL 0
#endif

#include <stdarg.h>

/* Filter the logging based on the provided level value
 * and the LOGGING_LEVEL constant. */
static void FilteredLog(int level, const char* fmt, ...)
{
    va_list args;
    char output[100];

    if (level <= LOGGING_LEVEL) {
        va_start(args, fmt);
        vsnprintf(output, sizeof(output), fmt, args);
        va_end(args);
        printf("%s", output);
    }
}

#if LOGGING_LEVEL > 0
    #define XLOG(...) do { if (1) FilteredLog(__VA_ARGS__); } while (0)
#else
    #define XLOG(...) do { if (0) FilteredLog(__VA_ARGS__); } while (0)
#endif
#define XERR(...) do { fprintf(stderr, __VA_ARGS__); } while (0)


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

    /* Read only. */
    struct sockaddr_in srvAddr;
} ginfo_t;

typedef struct tinfo_t {
    int idx;
    struct sockaddr_in addr;
} tinfo_t;


static ginfo_t gInfo =
    {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0};


static void *TimerWorker(void* arg)
{
    useconds_t timeout = (unsigned long)arg * 1000;
    int stop;

    do {
        XLOG(3, "Sleeping for %ums.\n", (unsigned long)arg);
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

        XLOG(2, "Key Change Server: %d.%d.%d.%d\n",
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
        XLOG(2, "Key Change Server: Switch!\n");

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
    unsigned long iteration = 0;
    int stop = 0, mcastTrigger, newMcastTrigger, status;
    unsigned short keyEpoch, newKeyEpoch, switchEpoch, newSwitchEpoch;
    KeyRespPacket_t keyResp;
    char message[128];
    int on = 1, mcastFd;

    XLOG(2, "1: Thread %d starting\n", tInfo->idx);

    keyEpoch = newKeyEpoch = switchEpoch = newSwitchEpoch = 0;
    mcastTrigger = newMcastTrigger = 0;
    memset(message, 0, sizeof(message));

    /* Make the mcast socket. */
    mcastFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (mcastFd < 0) {
        XLOG(1, "5: mcastFd socket fail\n");
        return NULL;
    }

    status = setsockopt(mcastFd,
                        SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (status < 0)
        return NULL;
#ifdef SO_REUSEPORT
    status = setsockopt(mcastFd,
                        SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    if (status < 0)
        return NULL;
#endif

    status = bind(mcastFd,
                  (struct sockaddr*)&tInfo->addr, sizeof(tInfo->addr));
    if (status != 0) {
        XLOG(1, "6: mcastFd socket bind fail\n");
        return NULL;
    }

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
            XLOG(3, "10: Thread %d getting epoch %hu\n",
                 tInfo->idx, newKeyEpoch);
            status = KeyClient_GetKey_ex(&gInfo.srvAddr.sin_addr,
                                         &tInfo->addr.sin_addr,
                                         &keyResp, NULL);
            if (status == 0) {
                unsigned short respEpoch =
                    (keyResp.epoch[0] << 8 | keyResp.epoch[1]);
                if (newKeyEpoch == respEpoch) {
                    XLOG(3, "11: Thread %d got epoch %hu\n",
                         tInfo->idx, newKeyEpoch);
                    keyEpoch = newKeyEpoch;
                }
            }
            else {
                XLOG(2, "13: Thread %d couldn't get key, "
                        "will try again later.\n", tInfo->idx);
            }
        }

        if (newSwitchEpoch != switchEpoch) {
            /* If the switch key is the same as our current keyEpoch,
             * switch over. */
            if (newSwitchEpoch == keyEpoch)  {
                XLOG(3, "12: Thread %d switching to epoch %hu\n",
                     tInfo->idx, newSwitchEpoch);
                switchEpoch = newSwitchEpoch;
            }
        }

        if (newMcastTrigger != mcastTrigger) {
            int sent;

            mcastTrigger = newMcastTrigger;
            sprintf(message, "Peer %02d sending message #%lu",
                    tInfo->idx, iteration);
            sent = (int)sendto(mcastFd, message, sizeof(message), 0,
                    (struct sockaddr*)&gInfo.srvAddr, sizeof(gInfo.srvAddr));
            if (sent != sizeof(message)) {
                XLOG(1, "couldn't send data\n");
            }

            iteration++;
        }
    }

    close(mcastFd);
    XLOG(3, "3: Thread %d ending\n", tInfo->idx);

    return NULL;
}


int main(int argc, char* argv[])
{
    tinfo_t blInfo; /* Broadcast listener thread info */
    pthread_t *kcPids = NULL; /* Key Client thread PIDs */
    tinfo_t *kcInfos = NULL; /* Key Client thread infos */
    tinfo_t *ti;
    pthread_t *pid;
    pthread_t timerPid;
    int status, i, tCount, ret = 1;
    char ipAddr[16] = "127.0.0.1";

    if (argc < 2) {
        XERR("need the thread count\n");
        goto exit;
    }

    tCount = atoi(argv[1]);
    if (tCount < 1 || tCount > MAX_THREAD_COUNT) {
        XERR("invalid thread count [1..%u]\n", MAX_THREAD_COUNT);
        goto exit;
    }

    kcPids = (pthread_t*)malloc(sizeof(pthread_t) * tCount);
    if (kcPids == NULL) {
        XLOG(1, "cannot allocate the pids array\n");
        goto exit;
    }

    kcInfos = (tinfo_t*)malloc(sizeof(tinfo_t) * tCount);
    if (kcInfos == NULL) {
        XLOG(1, "cannot allocate the thread infos array\n");
        goto exit;
    }

    memset(&gInfo.srvAddr, 0, sizeof(gInfo.srvAddr));
    memset(&blInfo, 0, sizeof(blInfo));
    memset(kcPids, 0, sizeof(pthread_t)*tCount);
    memset(kcInfos, 0, sizeof(tinfo_t)*tCount);

    status = pthread_mutex_init(&gInfo.mutex, NULL);
    if (status != 0) {
        XLOG(1, "cannot init mutex\n");
        goto exit;
    }

    status = pthread_cond_init(&gInfo.cond, NULL);
    if (status != 0) {
        XLOG(1, "cannot init cond\n");
        goto exit;
    }

    /* Set up the broadcast listener address. */
    blInfo.idx = -1;
    sprintf(ipAddr, "%s.1", gNetworkBase);
    inet_pton(AF_INET, ipAddr, &blInfo.addr.sin_addr);
    blInfo.addr.sin_family = AF_INET;
    blInfo.addr.sin_port = 0;

    /* Set up the key server address. */
    sprintf(ipAddr, "%s.2", gNetworkBase);
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
        if (status != 0)
            XLOG(1, "0: thread %d failed (%d)\n", i, status);
    }

    status = pthread_create(&timerPid, NULL, TimerWorker, (void*)750);
    if (status != 0)
        XLOG(1, "0: thread TIMER failed (%d)\n", status);

    status = KeyBcast_RunUdp(&blInfo.addr.sin_addr, KeyBcastCallback, NULL);
    if (status != 0) {
        XLOG(1, "KeyBcast failed %d\n", status);
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
    free(kcInfos);
    free(kcPids);

    return ret;
}
