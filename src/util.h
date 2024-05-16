#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>

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

char        *strdup(const char *s);
char        *str_replace(const char* s, const char* oldW, const char* newW);
bool         get_gateway(char *ip, char *dev);
char        *chipvpn_format_bytes(uint64_t bytes);
bool         chipvpn_secure_random(char *buf, int size);
uint64_t     chipvpn_get_time();

#ifdef __cplusplus
}
#endif

#endif