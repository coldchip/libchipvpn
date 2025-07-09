/* crc32.c -- compute the CRC-32 of a data stream
 * Copyright (C) 1995-1998 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

#include "crc32.h"

unsigned int crc32(const unsigned char *buffer, unsigned int len) {
	unsigned int crc;
	crc = 0;
	crc = crc ^ 0xffffffffL;
	while(len >= 8) {
		DO8(buffer);
		len -= 8;
	}
	if(len) do {
		DO1(buffer);
	} while(--len);
	return crc ^ 0xffffffffL;
}