#ifndef CHIPVPN_H
#define CHIPVPN_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>

#include "device.h"
#include "tun.h"
#include "socket.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

typedef struct {
	chipvpn_device_t *device;
	chipvpn_tun_t *tun;
	chipvpn_socket_t *sock;

	int tun_can_read;
	int tun_can_write;
	int sock_can_read;
	int sock_can_write;

	uint64_t counter;
	uint64_t sender_id;
	uint64_t last_update;
} chipvpn_t;

chipvpn_t *    chipvpn_init(char *config);
void           chipvpn_wait(chipvpn_t *vpn);
void           chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max);
void           chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset);
int            chipvpn_service(chipvpn_t *vpn);
void           chipvpn_print_stats(chipvpn_t *vpn);
void           chipvpn_cleanup(chipvpn_t *vpn);

char          *chipvpn_format_bytes(uint64_t bytes);
void           chipvpn_log(const char *format, ...);
uint32_t       chipvpn_get_time();

#ifdef __cplusplus
}
#endif

#endif