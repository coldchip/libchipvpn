#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SECURE32 __attribute__((cleanup(chipvpn_wipe_mem_32)))

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

char        *chipvpn_strdup(const char *s);
char        *chipvpn_read_file(const char *file);
char        *chipvpn_str_replace(const char *s, const char *old_word, const char *new_word);
char        *chipvpn_sgets(char *buf, int n, const char **str);
bool         chipvpn_get_gateway(char *ip, char *dev);
char        *chipvpn_format_bytes(uint64_t bytes);
bool         chipvpn_secure_random(uint8_t *buf, int size);
uint64_t     chipvpn_get_time();
int          chipvpn_secure_memcmp(const void *a, const void *b, size_t size);
void         chipvpn_secure_zero(void *v, size_t n);
float        chipvpn_log2(float val);
bool         chipvpn_check_key_randomness(const uint8_t *key, size_t length);

static inline void chipvpn_wipe_mem_32(uint8_t (*key)[32]) {
    chipvpn_secure_zero(key, 32);
}

#ifdef __cplusplus
}
#endif

#endif