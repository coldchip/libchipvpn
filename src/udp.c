#include "udp.h"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "chipvpn.h"
#include "util.h"
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

bool chipvpn_udp_init(chipvpn_udp_t *udp) {
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if(fd >= 0) {
		int v6_only = 0;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) < 0) {
			close(fd);
			fd = -1;
		}

		udp->family = AF_INET6;
	}

	if(fd < 0) {
		fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		if(fd < 0) {
			return false;
		}

		udp->family = AF_INET;
	}

	int reuse = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		close(fd);
		return false;
	}

	if(!chipvpn_queue_init(&udp->tx_queue, 32)) {
		close(fd);
		return false;
	}
	
	if(!chipvpn_queue_init(&udp->rx_queue, 32)) {
		chipvpn_queue_cleanup(&udp->tx_queue);
		close(fd);
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

bool chipvpn_udp_bind(chipvpn_udp_t *udp, const chipvpn_address_t *addr) {
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t len = 0;

	if(udp->family == AF_INET6) {
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
	} else if(udp->family == AF_INET) {
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

static inline bool chipvpn_udp_raw_read(chipvpn_udp_t *udp, chipvpn_queue_entry_t *entry) {
	ssize_t r = -1;

	/* read socket */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t len = sizeof(ss);

	r = recvfrom(udp->fd, entry->buffer, sizeof(entry->buffer), MSG_DONTWAIT, (struct sockaddr *)&ss, &len);

	if(r > 0) {
		if(udp->family == AF_INET6) {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;

			if(IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
				entry->addr.type = CHIPVPN_ADDRESS_IPV4;
				memcpy(&entry->addr.ipv4, &sa6->sin6_addr.s6_addr[12], sizeof(entry->addr.ipv4));
			} else {
				entry->addr.type = CHIPVPN_ADDRESS_IPV6;
				memcpy(&entry->addr.ipv6, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
			}
			
			entry->addr.port = ntohs(sa6->sin6_port);
		} else if(udp->family == AF_INET) {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
			entry->addr.type = CHIPVPN_ADDRESS_IPV4;
			entry->addr.ipv4 = sa4->sin_addr.s_addr;
			entry->addr.port = ntohs(sa4->sin_port);
		} else {
			return false;
		}
	}
		

	if(r <= 0) {
		/* drop if empty packet */
		return false;
	}

	entry->size = r;

	return true;
}

static inline bool chipvpn_udp_raw_write(chipvpn_udp_t *udp, chipvpn_queue_entry_t *entry) {
	ssize_t w = -1;

	/* write socket */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t len = 0;

	if(udp->family == AF_INET6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
		sa6->sin6_family = AF_INET6;

		if(entry->addr.type == CHIPVPN_ADDRESS_IPV4) {
			memset(&sa6->sin6_addr.s6_addr[0], 0, 10);
			memset(&sa6->sin6_addr.s6_addr[10], 0xff, 2);
			memcpy(&sa6->sin6_addr.s6_addr[12], &entry->addr.ipv4, sizeof(entry->addr.ipv4));
		} else {
			memcpy(&sa6->sin6_addr, &entry->addr.ipv6, sizeof(entry->addr.ipv6));
		}

		sa6->sin6_port = htons(entry->addr.port);
		len = sizeof(struct sockaddr_in6);
	} else if(udp->family == AF_INET) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = entry->addr.ipv4;
		sa4->sin_port = htons(entry->addr.port);
		len = sizeof(struct sockaddr_in);
	} else {
		return false;
	}

	w = sendto(udp->fd, entry->buffer, entry->size, 0, (struct sockaddr *)&ss, len);

	if(w <= 0) {
		/* drop if network is down */
		return !(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR); 
	}

	entry->size = 0;

	return true;
}

void chipvpn_udp_preselect(chipvpn_udp_t *udp, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_queue_push_acquire(&udp->rx_queue)) FD_SET(udp->fd, rdset); else FD_CLR(udp->fd, rdset);
	if(chipvpn_queue_pop_acquire(&udp->tx_queue))  FD_SET(udp->fd, wdset); else FD_CLR(udp->fd, wdset);
	*max = udp->fd;
}

void chipvpn_udp_postselect(chipvpn_udp_t *udp, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(udp->fd, rdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_push_acquire(&udp->rx_queue);
		if(entry && chipvpn_udp_raw_read(udp, entry)) {
			chipvpn_queue_push_commit(&udp->rx_queue, entry);
		}
	}

	if(FD_ISSET(udp->fd, wdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_pop_acquire(&udp->tx_queue);
		if(entry && chipvpn_udp_raw_write(udp, entry)) {
			chipvpn_queue_pop_commit(&udp->tx_queue, entry);
		}
	}
}

void chipvpn_udp_cleanup(chipvpn_udp_t *udp) {
	chipvpn_queue_cleanup(&udp->tx_queue);
	chipvpn_queue_cleanup(&udp->rx_queue);

	close(udp->fd);
}