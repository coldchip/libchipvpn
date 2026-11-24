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

bool                    chipvpn_udp_init(chipvpn_udp_t *udp);
bool                    chipvpn_udp_set_recvbuf(const chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_sendbuf(const chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_fwmark(const chipvpn_udp_t *sock, int fwmark);
bool                    chipvpn_udp_bind(const chipvpn_udp_t *udp, const chipvpn_address_t *address);

void                    chipvpn_udp_preselect(chipvpn_udp_t *udp, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_udp_postselect(chipvpn_udp_t *udp, fd_set *rdset, fd_set *wdset);

void                    chipvpn_udp_cleanup(chipvpn_udp_t *udp);

#ifdef __cplusplus
}
#endif

#endif