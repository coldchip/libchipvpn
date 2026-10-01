#include "util.h"
#include "base64.h"
#include "curve25519.h"
#include "chacha20poly1305.h"
#include "poly1305.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>

void chipvpn_print_key(uint8_t *key) {
	for(int i = 0; i < 32; i++) {
		printf("%02x", key[i] & 0xff);
	}
	printf("\n");

	char b64_key[45] = {0};
	memset(b64_key, 0, sizeof(b64_key));
	b64_encode(key, CURVE25519_KEY_SIZE, (uint8_t *)b64_key);
	chipvpn_log_append("key: %s\n", b64_key);
}

char *chipvpn_strdup(const char *s) {
	size_t len = strlen(s) + 1;
	void *new = malloc(len);
	if(new == NULL) {
		return NULL;
	}
	return (char*)memcpy(new, s, len);
}

char *chipvpn_read_file(const char *file) {
	FILE *infp = fopen(file, "rb");
	if(!infp) {
		return NULL;
	}
	fseek(infp, 0, SEEK_END);
	long fsize = ftell(infp);
	char *p = malloc(fsize + 1);
	fseek(infp, 0, SEEK_SET);

	if(fread((char*)p, 1, fsize, infp)) {}

	fclose(infp);
	*(p + fsize) = '\0';

	return p;
}

char* chipvpn_str_replace(const char* s, const char* oldW, const char* newW) { 
	char* result; 
	int i, cnt = 0; 
	int newWlen = strlen(newW); 
	int oldWlen = strlen(oldW); 
 
	// Counting the number of times old word 
	// occur in the string 
	for(i = 0; s[i] != '\0'; i++) { 
		if (strstr(&s[i], oldW) == &s[i]) { 
			cnt++; 
 
			// Jumping to index after the old word. 
			i += oldWlen - 1; 
		} 
	} 
 
	// Making new string of enough length 
	result = (char*)malloc(i + cnt * (newWlen - oldWlen) + 1); 
 
	i = 0; 
	while(*s) { 
		// compare the substring with the result 
		if(strstr(s, oldW) == s) { 
			strcpy(&result[i], newW); 
			i += newWlen; 
			s += oldWlen; 
		} else {
			result[i++] = *s++; 
		}
	} 
 
	result[i] = '\0'; 
	return result; 
}


char *chipvpn_sgets(char *buf, int n, const char **str) {
	const char *s = *str;
	const char *lf = strchr(s, '\n');
	int len = (lf == NULL) ? strlen(s) : (lf - s) + 1;

	if (len == 0)
		return NULL;
	if (len > n - 1)
		len = n - 1;

	memcpy(buf, s, len);
	buf[len] = 0;
	*str += len;
	return buf;
}

char *chipvpn_format_bytes(uint64_t bytes) {
	char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if(bytes > 1024) {
		for(i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024) {
			dblBytes = bytes / 1024.0;
		}
	}

	static char output[200];
	sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
	return output;
}

bool chipvpn_secure_random(uint8_t *buf, int size) {
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0) {
		return false;
	}

	int offset = 0, count;
	int tmp;

	while(size > 0) {
		count = size <= 8192 ? size : 8192;
		tmp = read(fd, (char *)buf + offset, count);
		if (tmp == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		if (tmp == -1) return -1; /* Unrecoverable IO error */
		offset += tmp;
		size -= tmp;
	}

	close(fd);

	return true;
}

uint64_t chipvpn_get_time() {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int chipvpn_secure_memcmp(const void *a, const void *b, size_t size) {
	const uint8_t *a_ptr = (const uint8_t *)a;
	const uint8_t *b_ptr = (const uint8_t *)b;
	uint32_t result = 0;

	for(size_t i = 0; i < size; i++) {
		result |= a_ptr[i] ^ b_ptr[i];
	}

	return result;
}

void chipvpn_secure_zero(void *v, size_t n) {
	volatile uint8_t *p = (volatile uint8_t *)v;
	while (n--) {
		*p++ = 0;
	}
}

float chipvpn_log2(float val) {
	union { float val; int32_t x; } u = { val };
	register float log_2 = (float)(((u.x >> 23) & 255) - 128);
	u.x   &= ~(255 << 23);
	u.x   += 127 << 23;
	log_2 += ((-0.3358287811f) * u.val + 2.0f) * u.val  -0.65871759316667f; 
	return (log_2);
}

static int count_set_bits(uint8_t byte) {
	int count = 0;
	while (byte) {
		count += byte & 1;
		byte >>= 1;
	}
	return count;
}

bool chipvpn_check_key_entropy(const uint8_t *key, size_t length) {
	if(!key || length == 0) return false;

	int total_bits = length * 8;
	int set_bits = 0;
	int byte_frequencies[256] = {0};

	for(size_t i = 0; i < length; i++) {
		set_bits += count_set_bits(key[i]);
		byte_frequencies[key[i]]++;
	}

	double bit_ratio = ((double)set_bits / total_bits) * 100.0;
	if(bit_ratio < 37.5 || bit_ratio > 62.5) {
		return false;
	}

	double entropy = 0.0;
	for(int i = 0; i < 256; i++) {
		if(byte_frequencies[i] > 0) {
			double p = (double)byte_frequencies[i] / length;
			entropy -= p * chipvpn_log2(p);
		}
	}

	double max_entropy = chipvpn_log2((double)length);
	if(max_entropy > 8.0) max_entropy = 8.0; 

	if(entropy < (max_entropy * 0.75)) {
		return false; 
	}

	return true;
}

void chipvpn_tai64n(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	// Get timestamp. Note that the timestamp must be synced by NTP, 
	//  or at least preserved in NVS, not to go back after reset.
	// Otherwise, the WireGuard remote peer rejects handshake.
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t millis = (uint64_t)(tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL));

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (millis / 1000);
	uint32_t nanos = (uint32_t)((millis % 1000) * 1000);
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}