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
#include <netinet/in.h>

bool chipvpn_udp_init(chipvpn_udp_t *udp, int fd) {
	bool owned_fd = false;

	if(fd < 0) {
		owned_fd = true;

		fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if(fd >= 0) {
			int v6_only = 0;
			if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) < 0) {
				close(fd);
				fd = -1;
			}
		}

		if(fd < 0) {
			fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
			if(fd < 0) {
				return false;
			}
		}
	}

	if(!chipvpn_socket_init(&udp->socket, fd)) {
		if(owned_fd) {
			close(fd);
		}
		return false;
	}

	udp->fd = fd;

	return true;
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

bool chipvpn_udp_bind(chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t len = 0;

	if(udp->socket.mode == CHIPVPN_ADDRESS_IPV6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
		sa6->sin6_family = AF_INET6;

		if(addr->type == CHIPVPN_ADDRESS_IPV4) {
			memset(&sa6->sin6_addr.s6_addr[0], 0, 10);
			memset(&sa6->sin6_addr.s6_addr[10], 0xff, 2);
			memcpy(&sa6->sin6_addr.s6_addr[12], &addr->ipv4, sizeof(addr->ipv4));
		} else {
			memcpy(&sa6->sin6_addr, &addr->ipv6, sizeof(sa6->sin6_addr));
		}
		
		sa6->sin6_port = htons(addr->port);
		len = sizeof(struct sockaddr_in6);
	} else if(udp->socket.mode == CHIPVPN_ADDRESS_IPV4) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = addr->ipv4;
		sa4->sin_port = htons(addr->port);
		len = sizeof(struct sockaddr_in);
	} else {
		return false;
	}

	return bind(udp->fd, (struct sockaddr *)&ss, len) == 0;
}

void chipvpn_udp_cleanup(chipvpn_udp_t *udp) {
	chipvpn_socket_cleanup(&udp->socket);
	close(udp->fd);
}