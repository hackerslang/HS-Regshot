/*
    Copyright 2026 Hackerslang

    This file is part of Regshot.

    Regshot is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2.1 of the License, or
    (at your option) any later version.

    Regshot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Regshot.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include "checksum.h"

LPTSTR ChecksumFromFile(LPTSTR filename, const LPTSTR alg)
{
    LPTSTR fileContents = ReadFileContents(filename);
    LPTSTR hash;

    if (0 != _tcsicmp(alg, "sha256")) {
        hash = SHA256Checksum(fileContents);
    }
    else {
        hash = SHA512Checksum(fileContents);
    }

    return hash;
}

LPTSTR ReadFileContents(const LPTSTR filename)
{
    LPTSTR buffer = NULL;
    size_t len;
    FILE* f = fopen(filename, "rb");

    if (f)
    {
        fseek(f, 0, SEEK_END);
        len = ftell(f);

        buffer = MYALLOC((len + 1) * sizeof(char));;

        fseek(f, 0, SEEK_SET);
        buffer = malloc(len);

        if (buffer)
        {
            for (int i = 0; i < len; i++) {
                fread(buffer + i, 1, 1, f);
            }
        }

        fclose(f);
    }

    return buffer;
}

LPTSTR SHA256Checksum(LPTSTR content) {
    size_t string_length = (size_t)strlen(content);

	SHA256 ctx;

	uint8_t hash_binary[SHA256_HASH_SIZE];
    char hash_hex[65];

    sha256_init(&ctx);
    sha256_update(&ctx, content, string_length);
    sha256_final(&ctx, hash_binary);

    sha256_to_string(&ctx, hash_hex);

    return hash_hex;
}

LPTSTR SHA512Checksum(LPTSTR content) {
    return content;
}