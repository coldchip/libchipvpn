#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include "socket.h"

chipvpn_socket_t *chipvpn_socket_create() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		return NULL;
	}

	chipvpn_socket_t *sock = malloc(sizeof(chipvpn_socket_t));
	sock->fd = fd;

	return sock;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}