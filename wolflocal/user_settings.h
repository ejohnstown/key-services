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
#define WOLFSSL_DTLS_DROP_STATS

#define THREADX
#define HAVE_THREADX
#undef HAVE_NETX
#define HAVE_NETX
#define NEED_THREADX_TYPES
#define THREADX_NO_DC_PRINTF

/* For wolftest, benchmark, and wolfcast */
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED

#define KEY_SOCKET_LOGGING_LEVEL 3
#define KEY_SERVICE_LOGGING_LEVEL 3
#define WOLFCAST_LOGGING_LEVEL 3
#define WOLFLOCAL_LOGGING_LEVEL 3
#if 1
//#define DEBUG_WOLFSSL
#define WOLFSSL_DEBUG_MEMORY
/* Enabling WOLFSSL_DEBUG_MEMORY requires modifying the file memory.c. It
 * calls printf() directly, and if you don't have it you'll get an error. */
#endif

#define WOLFSSL_MAX_MTU 512
#define WOLFMEM_BUCKETS 64,128,256,384,512,1024,4680,29696
#define WOLFMEM_DIST 14,4,6,8,4,2,4,1
#define WOLFMEM_MAX_BUCKETS 8
/* The static memory size is based on the above constants, and calculated
 * by the function wolfSSL_StaticBufferSz(). */
//#define WOLFLOCAL_STATIC_MEMORY_SZ 30000
#define WOLFLOCAL_STATIC_MEMORY_SZ 3000000

#define KEY_SOCKET_RECVFROM_TIMEOUT 300

#define CUSTOM_RAND_GENERATE_SEED(p, sz) mySeed(p, sz)
