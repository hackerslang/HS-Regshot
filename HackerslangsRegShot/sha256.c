/* Copyright (c) 2001-2003 Allan Saddi <allan@saddi.com>
 * Copyright (c) 2023 Rob Casey <rcasey@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ALLAN SADDI AND HIS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL ALLAN SADDI OR HIS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: sha256.c 680 2003-07-25 21:57:49Z asaddi $ */

#include <stdio.h>
#include <string.h>

#include "sha256.h"

static inline void _endian(int* endian);

static void _sha256_internal(SHA256* ctx, const uint32_t* cbuf);

#define ROTL(x, n)      (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n)      (((x) >> (n)) | ((x) << (32 - (n))))

#define Ch(x, y, z)     ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z)    (((x) & ((y) | (z))) | ((y) & (z)))
#define SIGMA0(x)       (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SIGMA1(x)       (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define sigma0(x)       (ROTR((x), 7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define sigma1(x)       (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

#define DO_ROUND() { \
    t1 = h + SIGMA1(e) + Ch(e, f, g) + *(Kp++) + *(W++); \
    t2 = SIGMA0(a) + Maj(a, b, c); \
    h = g; \
    g = f; \
    f = e; \
    e = d + t1; \
    d = c; \
    c = b; \
    b = a; \
    a = t1 + t2; \
}

#define BYTESWAP(x)     _byteswap(ctx->endian, x)
#define BYTESWAP64(x)   _byteswap64(ctx->endian, x)

#define _BYTESWAP(x)    ((ROTR((x), 8) & 0xff00ff00L) | (ROTL((x), 8) & 0x00ff00ffL))
#define _BYTESWAP64(x)  __byteswap64(x)


static const uint32_t K[64] = {
    0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
    0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
    0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
    0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
    0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
    0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
    0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
    0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
    0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
    0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
    0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
    0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
    0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
    0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
    0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
    0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L
};

static const uint8_t padding[64] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static inline uint64_t
__byteswap64(uint64_t x) {
    uint32_t a = x >> 32;
    uint32_t b = (uint32_t)x;
    return ((uint64_t)_BYTESWAP(b) << 32) | (uint64_t)_BYTESWAP(a);
}

static inline uint32_t
_byteswap(int little_endian, uint32_t x) {
    return (!little_endian) ? x : _BYTESWAP(x);
}

static inline uint64_t
_byteswap64(int little_endian, uint64_t x) {
    return (!little_endian) ? x : _BYTESWAP64(x);
}

static inline void
_endian(int* endian) {
    union {
        uint32_t w;
        uint8_t b[4];
    }
    str;

    str.w = 1L;
    *endian = (str.b[0] != 0);
}

static void
_sha256_internal(SHA256* ctx, const uint32_t* cbuf) {
    uint32_t buf[64];
    uint32_t* W, * W2, * W7, * W15, * W16;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    const uint32_t* Kp;
    int i;

    W = buf;

    for (i = 15; i >= 0; i--) {
        *(W++) = BYTESWAP(*cbuf);
        cbuf++;
    }

    W16 = &buf[0];
    W15 = &buf[1];
    W7 = &buf[9];
    W2 = &buf[14];

    for (i = 47; i >= 0; i--) {
        *(W++) = sigma1(*W2) + *(W7++) + sigma0(*W15) + *(W16++);
        W2++;
        W15++;
    }

    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    Kp = K;
    W = buf;

    for (i = 15; i >= 0; i--) {
        DO_ROUND();
        DO_ROUND();
        DO_ROUND();
        DO_ROUND();
    }

    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
}

/*!
    \fn void sha256_final(SHA256 *ctx, uint8_t *hash)
    \brief Complete SHA256 hash digest calculation
    \params ctx SHA256 contextual data structure
    \params hash Output buffer for SHA256 hash digest result
    \returns No return value

    This function completes the SHA256 hash digest calculation, processing any
    trailing bytes which have been cached, but yet processed due to the minimum
    length required for each SHA256 round of calculation. Additionally, if a
    non-null value is passed as hash argument, this is taken to be buffer into
    which the SHA256 hash result is populated.
*/

void
sha256_final(SHA256* ctx, uint8_t* hash) {
    uint32_t bytes;
    uint64_t length;
    int i;

    bytes = 120L - ctx->length;
    if (bytes > 64L) {
        bytes -= 64L;
    }
    length = BYTESWAP64(ctx->total);
    sha256_update(ctx, padding, bytes);
    sha256_update(ctx, &length, 8L);

    if (hash) {
        for (i = 0; i < SHA256_HASH_WORDS; i++) {
            hash[0] = (uint8_t)((ctx->hash[i] >> 24) & 0xff);
            hash[1] = (uint8_t)((ctx->hash[i] >> 16) & 0xff);
            hash[2] = (uint8_t)((ctx->hash[i] >> 8) & 0xff);
            hash[3] = (uint8_t)(ctx->hash[i] & 0xff);
            hash += 4;
        }
    }
}

/*!
    \fn void sha256_init(SHA256 *ctx)
    \brief Initialise SHA256 contextual data structure
    \params ctx SHA256 contextual data structure
    \returns No return value
*/

void
sha256_init(SHA256* ctx) {
    _endian(&ctx->endian);
    ctx->total = 0LL;
    ctx->hash[0] = 0x6a09e667L;
    ctx->hash[1] = 0xbb67ae85L;
    ctx->hash[2] = 0x3c6ef372L;
    ctx->hash[3] = 0xa54ff53aL;
    ctx->hash[4] = 0x510e527fL;
    ctx->hash[5] = 0x9b05688cL;
    ctx->hash[6] = 0x1f83d9abL;
    ctx->hash[7] = 0x5be0cd19L;
    ctx->length = 0L;
}

/*!
    \fn void sha256_to_string(SHA256 *ctx, char *str)
    \brief Generates a readable string output version of SHA256 hash digest
    \params ctx SHA256 contextual data structure
    \params str Pointer to string buffer
    \returns No return value
*/

void
sha256_to_string(SHA256* ctx, char* str, size_t str_size) {
    int i;
    size_t pos = 0;

    if (str == NULL || str_size == 0) {
        return;
    }

    /* Ensure empty string to start */
    str[0] = '\0';

    for (i = 0; i < SHA256_HASH_WORDS; ++i) {
        size_t remaining = (str_size > pos) ? (str_size - pos) : 0;
        if (remaining == 0) break;

        int written = sprintf_s(str + pos, remaining, "%02x%02x%02x%02x",
            ((ctx->hash[i] >> 24) & 0xff),
            ((ctx->hash[i] >> 16) & 0xff),
            ((ctx->hash[i] >> 8) & 0xff),
            (ctx->hash[i] & 0xff));

        if (written < 0) break; /* encoding error or truncated */

        pos += (size_t)written;
    }
}

void sha256_digest_to_string(const uint8_t digest[SHA256_HASH_SIZE], char* out, size_t out_size) {
    if (!out || out_size == 0) return;
    size_t pos = 0;
    out[0] = '\0';

    for (size_t i = 0; i < SHA256_HASH_SIZE; ++i) {
        size_t remaining = (out_size > pos) ? (out_size - pos) : 0;
        if (remaining < 3) break; // need 2 chars + null or more for following
        int written = sprintf_s(out + pos, remaining, "%02x", digest[i]);
        if (written < 0) break;
        pos += (size_t)written;
    }
}

/*!
    \fn void sha256_update(SGA256 *ctx, const void *data, uint32_t length)
    \brief Processes bytes to calculate SHA256 hash digest
    \params ctx SHA256 contextual data structure
    \params data Pointer to data bytes to be processes
    \params length Number of data bytes to process
    \returns No return value
*/

void
sha256_update(SHA256* ctx, const void* data, uint32_t length) {
    const uint8_t* d = data;
    uint32_t count;

    while (length) {
        count = 64L - ctx->length;
        if (count > length) {
            count = length;
        }
        memcpy(&ctx->buffer.bytes[ctx->length], d, count);
        ctx->total += count * 8L;
        ctx->length += count;
        d += count;
        length -= count;

        if (ctx->length == 64L) {
            _sha256_internal(ctx, ctx->buffer.words);
            ctx->length = 0L;
        }
    }
}
