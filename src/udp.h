#ifndef UDP_H
#define UDP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include "queue.h"

typedef struct {
	int family;
	int fd;
	chipvpn_queue_t tx_queue;
	chipvpn_queue_t rx_queue;
} chipvpn_udp_t;

bool                    chipvpn_udp_init(chipvpn_udp_t *udp, int fd);
bool                    chipvpn_udp_set_recvbuf(chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_sendbuf(chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_fwmark(chipvpn_udp_t *sock, int fwmark);
bool                    chipvpn_udp_bind(chipvpn_udp_t *sock, chipvpn_address_t *bind);

void                    chipvpn_udp_preselect(chipvpn_udp_t *udp, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_udp_postselect(chipvpn_udp_t *udp, fd_set *rdset, fd_set *wdset);

void                    chipvpn_udp_cleanup(chipvpn_udp_t *udp);

#ifdef __cplusplus
}
#endif

#endif