#include "udp.h"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/un.h>


chipvpn_udp_t *chipvpn_udp_create(int fd) {
	chipvpn_udp_t *udp = malloc(sizeof(chipvpn_udp_t));
	if(!udp) {
		return NULL;
	}

	if(fd < 0) {
		fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if(fd < 0) {
			return NULL;
		}
	}

	chipvpn_socket_t *sock = chipvpn_socket_create(fd);
	if(!sock) {
		return NULL;
	}

	udp->fd = fd;
	udp->socket = sock;

	return udp;
}

bool chipvpn_udp_set_recvbuf(chipvpn_udp_t *sock, int size) {
	return setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0;
}

bool chipvpn_udp_set_sendbuf(chipvpn_udp_t *sock, int size) {
	return setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0;
}

bool chipvpn_udp_set_fwmark(chipvpn_udp_t *sock, int fwmark) {
	return setsockopt(sock->fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) == 0;
}

bool chipvpn_udp_bind(chipvpn_udp_t *sock, chipvpn_address_t *addr) {
	if(addr->type != CHIPVPN_ADDRESS_IPV4) {
		return false;
	}

	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = addr->ipv4,
		.sin_port = htons(addr->port)
	};

	return bind(sock->fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
}

void chipvpn_udp_free(chipvpn_udp_t *udp) {
	chipvpn_socket_free(udp->socket);
	close(udp->fd);
	free(udp);
}