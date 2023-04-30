#ifndef CHIPVPN_H
#define CHIPVPN_H

#include <stdbool.h>
#include <stdint.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

void           chipvpn_setup(char *config);
void           chipvpn_init(char *config);
void           chipvpn_loop(char *config);
void           chipvpn_print_stats();
void           chipvpn_cleanup();
void           chipvpn_exit(int type);

char          *chipvpn_format_bytes(uint64_t bytes);
void           chipvpn_log(const char *format, ...);
void           chipvpn_error(const char *format, ...);
uint32_t       chipvpn_get_time();

#endif