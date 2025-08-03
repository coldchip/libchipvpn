#ifndef CHIPVPN_H
#define CHIPVPN_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <net/if.h>

#include "device.h"
#include "socket.h"

#define CHIPVPN_VERSION 300006
#define CHIPVPN_PROTOCOL_VERSION 197

#define CHIPVPN_PEER_TIMEOUT 15000
#define CHIPVPN_PEER_PING 2000

typedef struct {
	chipvpn_device_t *device;
	chipvpn_socket_t *socket;
	chipvpn_socket_t *ipc;
} chipvpn_t;

chipvpn_t *    chipvpn_create(int tun_fd);
void           chipvpn_poll(chipvpn_t *vpn, uint64_t timeout);
void           chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max);
void           chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset);
int            chipvpn_service(chipvpn_t *vpn);
void           chipvpn_cleanup(chipvpn_t *vpn);

#ifdef __cplusplus
}
#endif

#endif