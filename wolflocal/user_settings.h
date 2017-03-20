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

#define THREADX
#define HAVE_THREADX
#undef HAVE_NETX
#define HAVE_NETX
#define NEED_THREADX_TYPES

/* For wolftest, benchmark, and wolfcast */
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED


int mySeed(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED(p, sz) mySeed(p, sz)
