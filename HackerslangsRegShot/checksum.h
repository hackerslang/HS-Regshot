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

#ifndef REGSHOT_CHECKSUM_H
#define REGSHOT_CHECKSUM_H
#pragma once

#include "common.h"
#include "sha256.h"
#include "sha512.h"

LPTSTR ChecksumFromFile(LPTSTR filename, const LPTSTR alg);
unsigned char* ReadFileContents(LPCTSTR filename, size_t* out_len);
LPTSTR SHA256Checksum(LPTSTR content);
LPTSTR SHA512Checksum(LPTSTR content);

#endif