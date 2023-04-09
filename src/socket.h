#ifndef SOCKET_H
#define SOCKET_H

#include <arpa/inet.h>
#include "address.h"

typedef struct {
	int fd;
} chipvpn_socket_t;

chipvpn_socket_t    *chipvpn_socket_create();
bool                 chipvpn_socket_bind(chipvpn_socket_t *sock, chipvpn_address_t *addr);
int                  chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
int                  chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
void                 chipvpn_socket_free(chipvpn_socket_t *sock);

#endif