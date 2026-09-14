#include "util.h"
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

char *chipvpn_strdup(const char *s) {
	size_t len = strlen(s) + 1;
	char *copy = malloc(len);
	if(copy == NULL) {
		return NULL;
	}
	return (char*)memcpy(copy, s, len);
}

/*
 * Read the entire contents of a file into a newly allocated,
 * NUL-terminated buffer. Returns NULL on any error. The caller
 * owns the returned buffer and must free() it.
 */
char *chipvpn_read_file(const char *file) {
	FILE *infp = fopen(file, "rb");
	if(!infp) {
		return NULL;
	}

	if(fseek(infp, 0, SEEK_END) != 0) {
		fclose(infp);
		return NULL;
	}

	long fsize = ftell(infp);
	if(fsize < 0) {
		fclose(infp);
		return NULL;
	}
	rewind(infp);

	char *p = malloc(fsize + 1);
	if(!p) {
		fclose(infp);
		return NULL;
	}

	if(fread(p, 1, fsize, infp) != (size_t)fsize) {
		free(p);
		fclose(infp);
		return NULL;
	}

	fclose(infp);
	p[fsize] = '\0';

	return p;
}

/*
 * Return a newly allocated copy of s with every occurrence of old_word
 * replaced by new_word. The caller owns the returned buffer.
 */
char *chipvpn_str_replace(const char *s, const char *old_word, const char *new_word) {
	int new_len = strlen(new_word);
	int old_len = strlen(old_word);

	/* count occurrences of old_word */
	int i, count = 0;
	for(i = 0; s[i] != '\0'; i++) {
		if(strstr(&s[i], old_word) == &s[i]) {
			count++;
			i += old_len - 1;
		}
	}

	char *result = malloc(i + count * (new_len - old_len) + 1);
	if(!result) {
		return NULL;
	}

	i = 0;
	while(*s) {
		if(strstr(s, old_word) == s) {
			strcpy(&result[i], new_word);
			i += new_len;
			s += old_len;
		} else {
			result[i++] = *s++;
		}
	}

	result[i] = '\0';
	return result;
}

/*
 * Read one line (up to n bytes) from the string pointed to by *str,
 * advancing *str past the consumed line. Returns buf, or NULL at end.
 */
char *chipvpn_sgets(char *buf, int n, const char **str) {
	const char *s = *str;
	const char *lf = strchr(s, '\n');
	int len = (lf == NULL) ? (int)strlen(s) : (int)(lf - s) + 1;

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

/*
 * Read a leading, filtered token from a popen'd command into out.
 * Keeps only characters accepted by is_valid and NUL-terminates.
 * Returns true on success.
 */
static bool chipvpn_read_route_field(const char *cmd, char *out, size_t out_size, bool (*is_valid)(char)) {
	FILE *fp = popen(cmd, "r");
	if(!fp) {
		return false;
	}

	bool success = fgets(out, out_size, fp) != NULL;
	out[out_size - 1] = '\0';

	pclose(fp);

	if(!success) {
		out[0] = '\0';
		return false;
	}

	size_t i = 0;
	while(out[i] != '\0' && is_valid(out[i])) {
		i++;
	}
	out[i] = '\0';

	return true;
}

static bool chipvpn_is_ip_char(char c) {
	return (c >= '0' && c <= '9') || c == '.';
}

static bool chipvpn_is_dev_char(char c) {
	return (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') ||
	       c == '-' || c == '_';
}

/*
 * Look up the system default gateway IP and/or the interface name.
 * Either pointer may be NULL. Buffers must be at least 16 bytes.
 */
bool chipvpn_get_gateway(char *ip, char *dev) {
	bool success = true;

	if(ip) {
		if(!chipvpn_read_route_field(
			"ip route show default | awk '/default/ {print $3}'",
			ip, 16, chipvpn_is_ip_char)) {
			success = false;
		}
	}

	if(dev) {
		if(!chipvpn_read_route_field(
			"ip route show default | awk '/default/ {print $5}'",
			dev, 16, chipvpn_is_dev_char)) {
			success = false;
		}
	}

	return success;
}

/*
 * Format a byte count into a human-readable string.
 * NOT re-entrant: returns a pointer to a static buffer.
 */
char *chipvpn_format_bytes(uint64_t bytes) {
	static const char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
	int count = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double value = bytes;

	if(bytes > 1024) {
		for(i = 0; (bytes / 1024) > 0 && i < count - 1; i++, bytes /= 1024) {
			value = bytes / 1024.0;
		}
	}

	static char output[200];
	snprintf(output, sizeof(output), "%.02lf %s", value, suffix[i]);
	return output;
}

bool chipvpn_secure_random(uint8_t *buf, int size) {
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0) {
		return false;
	}

	int offset = 0;
	while(size > 0) {
		int count = size <= 8192 ? size : 8192;
		int got = read(fd, buf + offset, count);
		if(got == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		if(got == -1) {
			/* unrecoverable IO error */
			close(fd);
			return false;
		}
		offset += got;
		size -= got;
	}

	close(fd);
	return true;
}

uint64_t chipvpn_get_time() {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	return ((int64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

/*
 * Constant-time comparison of two buffers. Returns 0 when equal,
 * non-zero otherwise. Does not short-circuit, to avoid timing leaks.
 */
int chipvpn_secure_memcmp(const void *a, const void *b, size_t size) {
	const uint8_t *a_ptr = (const uint8_t *)a;
	const uint8_t *b_ptr = (const uint8_t *)b;
	uint32_t result = 0;

	for(size_t i = 0; i < size; i++) {
		result |= a_ptr[i] ^ b_ptr[i];
	}

	return result;
}

/*
 * Zero a buffer in a way the compiler is not permitted to optimise away.
 */
void chipvpn_secure_zero(void *v, size_t n) {
	volatile uint8_t *p = (volatile uint8_t *)v;
	while(n--) {
		*p++ = 0;
	}
}

/*
 * Fast approximate base-2 logarithm using IEEE-754 bit manipulation.
 * Used only for the coarse entropy heuristic below.
 */
float chipvpn_log2(float val) {
	union { float val; int32_t x; } u = { val };
	float log_2 = (float)(((u.x >> 23) & 255) - 128);
	u.x &= ~(255 << 23);
	u.x += 127 << 23;
	log_2 += ((-0.3358287811f) * u.val + 2.0f) * u.val - 0.65871759316667f;
	return log_2;
}

static int count_set_bits(uint8_t byte) {
	int count = 0;
	while(byte) {
		count += byte & 1;
		byte >>= 1;
	}
	return count;
}

/*
 * Heuristic sanity check that a key looks random: the fraction of set bits
 * should be near 50% and the byte-value entropy should be reasonably high.
 * This is a cheap guard against obviously weak / repeating keys, not a
 * cryptographic randomness test.
 */
bool chipvpn_check_key_randomness(const uint8_t *key, size_t length) {
	if(!key || length == 0) {
		return false;
	}

	/* acceptable window for the ratio of set bits (percent) */
	const double min_bit_ratio = 37.5;
	const double max_bit_ratio = 62.5;
	/* required fraction of the maximum possible byte entropy */
	const double min_entropy_ratio = 0.75;

	int total_bits = length * 8;
	int set_bits = 0;
	int byte_frequencies[256] = {0};

	for(size_t i = 0; i < length; i++) {
		set_bits += count_set_bits(key[i]);
		byte_frequencies[key[i]]++;
	}

	double bit_ratio = ((double)set_bits / total_bits) * 100.0;
	if(bit_ratio < min_bit_ratio || bit_ratio > max_bit_ratio) {
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
	if(max_entropy > 8.0) {
		max_entropy = 8.0;
	}

	if(entropy < (max_entropy * min_entropy_ratio)) {
		return false;
	}

	return true;
}
