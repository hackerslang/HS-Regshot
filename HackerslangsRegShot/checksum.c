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
#include <windows.h> 
#include <tchar.h>
#include <stdlib.h>
#include <string.h>

LPTSTR ChecksumFromFile(LPTSTR filename, const LPTSTR alg)
{
    size_t out_len;
    unsigned char* fileContents = ReadFileContents(filename, &out_len);
    LPTSTR hash;

    if (0 != _tcsicmp(alg, "sha256")) {
        hash = SHA256Checksum(fileContents);
    }
    else {
        hash = SHA512Checksum(fileContents);
    }

    return hash;
}

unsigned char* ReadFileContents(LPCTSTR filename, size_t* out_len) {
    HANDLE h = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { *out_len = 0; return NULL; }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) { CloseHandle(h); *out_len = 0; return NULL; }

    size_t len = (size_t)sz.QuadPart;
    unsigned char* buf = (unsigned char*)MYALLOC0(len); // or malloc(len)
    if (!buf) { CloseHandle(h); *out_len = 0; return NULL; }

    DWORD read = 0;
    if (!ReadFile(h, buf, (DWORD)len, &read, NULL) || (size_t)read != len) {
        MYFREE(buf); // or free(buf)
        CloseHandle(h);
        *out_len = 0;
        return NULL;
    }

    CloseHandle(h);
    *out_len = len;
    return buf;
}

LPTSTR SHA256Checksum(LPTSTR content) {
    if (NULL == content) { return TEXT(""); }

    size_t string_length = (size_t)_tcslen(content);

	SHA256 ctx;

	uint8_t hash_binary[SHA256_HASH_SIZE];
    char *hash_hex = NULL;

    sha256_init(&ctx);
    sha256_update(&ctx, content, string_length);
    sha256_final(&ctx, hash_binary);

    /* Allocate heap buffer for hex string (64 chars + null) */
    hash_hex = (char *)MYALLOC0(65);
    if (NULL == hash_hex) { return TEXT(""); }

    /* Use safe conversion that knows the buffer size */
    sha256_to_string(&ctx, hash_hex, 65);

    size_t strLen = strlen(hash_hex) + 1;
    LPTSTR str = MYALLOC0(strLen * sizeof(TCHAR));

    size_t n = 0;
    mbstowcs_s(&n, str, strLen, hash_hex, strlen(hash_hex));
    
    if (str[strLen - 1] != (TCHAR)'\0') {
        str[strLen - 1] = TEXT("\0");
    }

	MYFREE(hash_hex);
    
    return str;
}

LPTSTR SHA512Checksum(LPTSTR content) {
    return content;
}