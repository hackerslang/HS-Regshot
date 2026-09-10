#ifndef _SHA256_H_
#define _SHA256_H_

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
 * $Id: sha256.h 348 2003-02-23 22:12:06Z asaddi $ */

#include <stdint.h>

#define SHA256_HASH_SIZE        (32)
#define SHA256_HASH_WORDS       (8)

typedef struct _SHA256 {

    uint32_t hash[SHA256_HASH_WORDS];

    uint32_t length;

    uint64_t total;

    union {
        uint32_t words[16];

        uint8_t bytes[64];
    }
    buffer;

    int endian;
}
SHA256;

void sha256_final(SHA256* ctx, uint8_t* hash);

void sha256_init(SHA256* ctx);

void sha256_to_string(SHA256* ctx, char* str);

void sha256_update(SHA256* ctx, const void* data, uint32_t length);

#endif  /* _SHA256_H_ */
