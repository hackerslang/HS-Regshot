#ifndef FILESHOT_CRYPT_SHA256
#define FILESHOT_CRYPT_SHA256
#pragma once

#include <cstddef>
#include "endian.h"

unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md);

#define SHA256_DIGEST_LENGTH 32

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define SHA256_CBLOCK (SHA_LBLOCK * 4) /* SHA-256 treats input data as a  \
                                        * contiguous array of 32 bit wide \
                                        * big-endian values. */

typedef struct SHA256state_st {
    SHA_LONG h[8]; /* Hash values (32 bytes) */
    SHA_LONG Nl, Nh; /* The length of the message in bits is stored into 64 bits */
    SHA_LONG data[SHA_LBLOCK]; /* Buffer used to store input less than 512 bits */
    unsigned int num; /* The size of the partial buffered input in data[] */
    unsigned int md_len; /* The output size (used for truncation) */
} SHA256_CTX;

OSSL_DEPRECATEDIN_3_0 int SHA256_Init(SHA256_CTX* c);
OSSL_DEPRECATEDIN_3_0 int SHA256_Update(SHA256_CTX* c,
    const void* data, size_t len);
OSSL_DEPRECATEDIN_3_0 int SHA256_Final(unsigned char* md, SHA256_CTX* c);
OSSL_DEPRECATEDIN_3_0 void SHA256_Transform(SHA256_CTX* c,
    const unsigned char* data);
#endif

unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md);

#define SHA256_192_DIGEST_LENGTH 24

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
 /*
  * SHA-512 treats input data as a
  * contiguous array of 64 bit
  * wide big-endian values.
  */
#define SHA512_CBLOCK (SHA_LBLOCK * 8)
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef unsigned __int64 SHA_LONG64;
#elif defined(__arch64__)
typedef unsigned long SHA_LONG64;
#else
typedef unsigned long long SHA_LONG64;
#endif

typedef struct SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

OSSL_DEPRECATEDIN_3_0 int SHA384_Init(SHA512_CTX* c);
OSSL_DEPRECATEDIN_3_0 int SHA384_Update(SHA512_CTX* c,
    const void* data, size_t len);
OSSL_DEPRECATEDIN_3_0 int SHA384_Final(unsigned char* md, SHA512_CTX* c);
OSSL_DEPRECATEDIN_3_0 int SHA512_Init(SHA512_CTX* c);
OSSL_DEPRECATEDIN_3_0 int SHA512_Update(SHA512_CTX* c,
    const void* data, size_t len);
OSSL_DEPRECATEDIN_3_0 int SHA512_Final(unsigned char* md, SHA512_CTX* c);
OSSL_DEPRECATEDIN_3_0 void SHA512_Transform(SHA512_CTX* c,
    const unsigned char* data);
#endif

unsigned char* SHA384(const unsigned char* d, size_t n, unsigned char* md);
unsigned char* SHA512(const unsigned char* d, size_t n, unsigned char* md);

#ifdef __cplusplus
}
#endif


#endif
