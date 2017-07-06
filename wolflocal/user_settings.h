#define NO_FILESYSTEM
#define NO_ASN
#define NO_BIG_INT
#define NO_RABBIT
#define NO_RSA
#define NO_DSA
#define NO_DES3
#define NO_HC128
#define NO_DH
#define NO_CERTS
#define NO_PWDBASED
#define NO_MD4
#define NO_MD5
#define NO_ERROR_STRINGS
#define NO_OLD_TLS
#define NO_RC4
#define NO_WRITEV
#define NO_SESSION_CACHE
#define NO_DEV_RANDOM
#define NO_SHA
#define HAVE_NULL_CIPHER
#define WOLFSSL_USER_IO
#define WOLFSSL_STATIC_PSK
#define HAVE_HASHDRBG
#define WOLFSSL_MULTICAST
#define WOLFSSL_DTLS
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_ALIGN 4
#define WOLFSSL_NO_MALLOC
#define NO_64BIT
#define BIG_ENDIAN_ORDER
#define USER_TICKS
#define WOLFSSL_DTLS_ALLOW_FUTURE

#define THREADX
#define HAVE_THREADX
#undef HAVE_NETX
#define HAVE_NETX
#define NEED_THREADX_TYPES

/* For wolftest, benchmark, and wolfcast */
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED

#ifdef PGB000
    #define LOCAL_ADDR "192.168.20.20"
    #define KEY_SERV_LOCAL_ADDR 192,168,20,20
    /* My local DHCP server always provides this address to PGB000. */
#else
    #define LOCAL_ADDR "192.168.20.21"
    #define KEY_SERV_LOCAL_ADDR 192,168,20,20
    /* PGB002 isn't using DHCP, it is hardcoded to this address. */
#endif
#define KEY_BCAST_ADDR 192,168,20,255

#define KEY_SOCKET_LOGGING_LEVEL 3
#define KEY_SERVICE_LOGGING_LEVEL 3
#define WOLFCAST_LOGGING_LEVEL 3
#define WOLFLOCAL_LOGGING_LEVEL 3
#if 0
#define DEBUG_WOLFSSL
#define WOLFSSL_DEBUG_MEMORY
#endif

#ifdef PGB000
    #define WOLFLOCAL_TEST_KEY_SERVER
#else /* PGB000/PGB002 */
    /*#define WOLFLOCAL_TEST_KEY_REQUEST*/
#endif /* PGB002 */

#define WOLFSSL_MAX_MTU 256
#define WOLFMEM_BUCKETS 64,128,256,384,1024,4544
#define WOLFMEM_DIST 14,4,6,8,4,4
#define WOLFMEM_MAX_BUCKETS 6
/* The static memory size is based on the above constants, and calculated
 * by the function wolfSSL_StaticBufferSz(). */
#define WOLFLOCAL_STATIC_MEMORY_SZ 25424

#define KEY_SOCKET_RECVFROM_TIMEOUT 300

int mySeed(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED(p, sz) mySeed(p, sz)
