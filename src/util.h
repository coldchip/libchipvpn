#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

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
char        *chipvpn_str_replace(const char* s, const char* oldW, const char* newW);
bool         chipvpn_get_gateway(char *ip, char *dev);
char        *chipvpn_format_bytes(uint64_t bytes);
bool         chipvpn_secure_random(uint8_t *buf, int size);
uint64_t     chipvpn_get_time();
int          chipvpn_secure_memcmp(const void *a, const void *b, size_t size);

#ifdef __cplusplus
}
#endif

#endif