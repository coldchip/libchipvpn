#ifndef SOCKET_H
#define SOCKET_H

typedef struct {
	int fd;
} chipvpn_socket_t;

chipvpn_socket_t    *chipvpn_socket_create();
void                 chipvpn_socket_free(chipvpn_socket_t *sock);

#endif