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
#include "device.h"
#include "socket.h"

#define CHIPVPN_PEER_TIMEOUT 10000
#define CHIPVPN_PEER_PING 2000

typedef struct {
	char name[IFNAMSIZ + 1];
	chipvpn_address_t network;
	int mtu;
	bool is_bind;
	chipvpn_address_t bind;
	char xorkey[1024];
	int sendbuf;
	int recvbuf;
} chipvpn_config_t;

typedef struct {
	chipvpn_device_t *device;
	chipvpn_socket_t *socket;
	uint64_t counter;
} chipvpn_t;

chipvpn_t *    chipvpn_create(chipvpn_config_t *config);
void           chipvpn_wait(chipvpn_t *vpn, uint64_t timeout);
void           chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max);
void           chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset);
int            chipvpn_service(chipvpn_t *vpn);
void           chipvpn_cleanup(chipvpn_t *vpn);

#ifdef __cplusplus
}
#endif

#endif