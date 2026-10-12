#ifndef UDP_H
#define UDP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include "socket.h"

typedef struct {
    int fd;
    chipvpn_socket_t *socket;
} chipvpn_udp_t;

chipvpn_udp_t          *chipvpn_udp_create(int fd);
bool                    chipvpn_udp_set_recvbuf(chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_sendbuf(chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_fwmark(chipvpn_udp_t *sock, int fwmark);
bool                    chipvpn_udp_bind(chipvpn_udp_t *sock, chipvpn_address_t *bind);
void                    chipvpn_udp_free(chipvpn_udp_t *udp);

#ifdef __cplusplus
}
#endif

#endif