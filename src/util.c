#include "util.h"
#include "log.h"
#include "base64.h"
#include "curve25519.h"
#include "chacha20poly1305.h"
#include "poly1305.h"
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
#include <stdarg.h>

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

char *chipvpn_sgets(char *buf, int n, const char **str) {
	const char *s = *str;
	const char *lf = strchr(s, '\n');
	int len = (lf == NULL) ? strlen(s) : (lf - s) + 1;

	if(len == 0) {
		return NULL;
	}

	if(len > n - 1) {
		len = n - 1;
	}

	memcpy(buf, s, len);
	buf[len] = 0;
	*str += len;
	return buf;
}

char *chipvpn_format_bytes(uint64_t bytes) {
	static const char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
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
		if(tmp == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		if(tmp == -1) {
			close(fd);
			return false;
		}
		offset += tmp;
		size -= tmp;
	}

	close(fd);

	return true;
}

bool chipvpn_run_command(const char *command) {
	if(!command) {
		return false;
	}

	int status = system(command);
	if(status == -1) {
		return false;
	}

	return WIFEXITED(status) && (WEXITSTATUS(status) == 0);
}

#define CHIPVPN_TIME_EPOCH_OFFSET (365ULL * 24ULL * 60ULL * 60ULL * 1000ULL)

#ifdef CLOCK_BOOTTIME
#define CHIPVPN_MONO_CLOCK CLOCK_BOOTTIME
#else
#define CHIPVPN_MONO_CLOCK CLOCK_MONOTONIC
#endif

uint64_t chipvpn_get_monotime(void) {
	struct timespec ts;

	if(clock_gettime(CHIPVPN_MONO_CLOCK, &ts) == 0) {
		return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL) + CHIPVPN_TIME_EPOCH_OFFSET;
	}

	return CHIPVPN_TIME_EPOCH_OFFSET;
}

uint64_t chipvpn_get_realtime() {
	struct timespec ts;

	if(clock_gettime(CLOCK_REALTIME, &ts) == 0) {
		return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
	}

	return 0ULL;
}

static uint64_t cached_time = 0ULL;

void chipvpn_update_tick() {
	cached_time = chipvpn_get_monotime();
}

uint64_t chipvpn_get_tick() {
	if(cached_time == 0ULL) {
		cached_time = chipvpn_get_monotime();
	}

	return cached_time;
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
	while(n--) {
		*p++ = 0;
	}
}

void chipvpn_tai64n(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	// Get timestamp. Note that the timestamp must be synced by NTP, 
	//  or at least preserved in NVS, not to go back after reset.
	// Otherwise, the WireGuard remote peer rejects handshake.
	uint64_t millis = chipvpn_get_realtime();

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (millis / 1000);
	uint32_t nanos = (uint32_t)((millis % 1000) * 1000);
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}