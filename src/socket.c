#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include "socket.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "packet.h"
#include "chipvpn.h"
#include "util.h"

bool chipvpn_socket_init(chipvpn_socket_t *sock, int fd, int queue_size) {
	if(fd < 0 || fd >= FD_SETSIZE) {
		return false;
	}

	/* queue_size must be the power of 2 */
	if(queue_size == 0 || (queue_size & (queue_size - 1)) != 0) {
		return false;
	}

	chipvpn_secure_zero(sock, sizeof(chipvpn_socket_t));

	int flags = fcntl(fd, F_GETFL, 0);
	if(flags == -1) {
		return false;
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}

	sock->fd = fd;
	sock->mode = chipvpn_socket_get_mode(fd);
	sock->type = chipvpn_socket_get_type(fd);

	sock->tx_queue.pool = malloc(queue_size * sizeof(chipvpn_socket_queue_entry_t));
	if(!sock->tx_queue.pool) {
		return false;
	}

	sock->rx_queue.pool = malloc(queue_size * sizeof(chipvpn_socket_queue_entry_t));
	if(!sock->rx_queue.pool) {
		return false;
	}

	sock->tx_queue.total_size = queue_size;
	sock->rx_queue.total_size = queue_size;

	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	return true;
}

chipvpn_address_type_e chipvpn_socket_get_mode(int fd) {
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	if(getsockname(fd, (struct sockaddr *)&ss, &len) < 0) {
		return CHIPVPN_ADDRESS_NONE;
	}

	if(ss.ss_family == AF_INET) {
		return CHIPVPN_ADDRESS_IPV4;
	}

	if(ss.ss_family == AF_INET6) {
		return CHIPVPN_ADDRESS_IPV6;
	}

	return CHIPVPN_ADDRESS_NONE;
}

chipvpn_socket_type_e chipvpn_socket_get_type(int fd) {
    int optval;
    socklen_t optlen = sizeof(optval);

    if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) < 0) {
        return CHIPVPN_SOCKET_DEV; 
    }

    if(optval == SOCK_STREAM) {
        return CHIPVPN_SOCKET_STREAM; 
    }

    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    
    if(getpeername(fd, (struct sockaddr*)&peer, &peer_len) == 0) {
        return CHIPVPN_SOCKET_STREAM; 
    }

    return CHIPVPN_SOCKET_DGRAM; 
}

bool chipvpn_socket_raw_read(chipvpn_socket_t *sock, chipvpn_socket_queue_entry_t *entry) {
	ssize_t r = -1;

	/* read socket */

	switch(sock->type) {
		case CHIPVPN_SOCKET_STREAM: {
			r = recv(sock->fd, entry->buffer, sizeof(entry->buffer), MSG_DONTWAIT);
		}
		break;
		case CHIPVPN_SOCKET_DEV: {
			r = read(sock->fd, entry->buffer, sizeof(entry->buffer));
		}
		break;
		case CHIPVPN_SOCKET_DGRAM: {
			struct sockaddr_storage ss;
			memset(&ss, 0, sizeof(ss));
			socklen_t len = sizeof(ss);

			r = recvfrom(sock->fd, entry->buffer, sizeof(entry->buffer), MSG_DONTWAIT, (struct sockaddr *)&ss, &len);

			if(r > 0) {
				if(sock->mode == CHIPVPN_ADDRESS_IPV6) {
					struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;

					if(IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
						entry->addr.type = CHIPVPN_ADDRESS_IPV4;
						memcpy(&entry->addr.ipv4, &sa6->sin6_addr.s6_addr[12], sizeof(entry->addr.ipv4));
					} else {
						entry->addr.type = CHIPVPN_ADDRESS_IPV6;
						memcpy(&entry->addr.ipv6, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
					}
					
					entry->addr.port = ntohs(sa6->sin6_port);
				} else if(sock->mode == CHIPVPN_ADDRESS_IPV4) {
					struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
					entry->addr.type = CHIPVPN_ADDRESS_IPV4;
					entry->addr.ipv4 = sa4->sin_addr.s_addr;
					entry->addr.port = ntohs(sa4->sin_port);
				}
			}
		}
		break;
	}

	if(r <= 0) {
		/* drop if empty packet */
		return false;
	}

	entry->size = r;

	return true;
}

bool chipvpn_socket_raw_write(chipvpn_socket_t *sock, chipvpn_socket_queue_entry_t *entry) {
	ssize_t w = -1;

	/* write socket */

	switch(sock->type) {
		case CHIPVPN_SOCKET_STREAM: {
			w = send(sock->fd, entry->buffer, entry->size, MSG_NOSIGNAL);
		}
		break;
		case CHIPVPN_SOCKET_DEV: {
			w = write(sock->fd, entry->buffer, entry->size);
		}
		break;
		case CHIPVPN_SOCKET_DGRAM: {
			struct sockaddr_storage ss;
			memset(&ss, 0, sizeof(ss));
			socklen_t len = 0;

			if(sock->mode == CHIPVPN_ADDRESS_IPV6) {
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
			} else if(sock->mode == CHIPVPN_ADDRESS_IPV4) {
				struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
				sa4->sin_family = AF_INET;
				sa4->sin_addr.s_addr = entry->addr.ipv4;
				sa4->sin_port = htons(entry->addr.port);
				len = sizeof(struct sockaddr_in);
			}

			w = sendto(sock->fd, entry->buffer, entry->size, 0, (struct sockaddr *)&ss, len);
		}
		break;
	}

	if(w <= 0) {
		/* drop if network is down */
		return !(errno == EAGAIN || errno == EWOULDBLOCK); 
	}

	entry->size = 0;

	return true;
}

void chipvpn_socket_preselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_socket_can_enqueue(sock)) FD_SET(sock->fd, rdset); else FD_CLR(sock->fd, rdset);
	if(chipvpn_socket_can_dequeue(sock)) FD_SET(sock->fd, wdset); else FD_CLR(sock->fd, wdset);
	*max = sock->fd;
}

void chipvpn_socket_postselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset) {
	chipvpn_socket_postselect_rdset(sock, rdset);
	chipvpn_socket_postselect_wdset(sock, wdset);
}

void chipvpn_socket_postselect_rdset(chipvpn_socket_t *sock, fd_set *rdset) {
	if(FD_ISSET(sock->fd, rdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->rx_queue);
		if(!entry) {
			return;
		}

		if(!chipvpn_socket_raw_read(sock, entry)) {
			return;
		}

		chipvpn_socket_enqueue_commit(&sock->rx_queue, entry);
	}
}

void chipvpn_socket_postselect_wdset(chipvpn_socket_t *sock, fd_set *wdset) {
	if(FD_ISSET(sock->fd, wdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&sock->tx_queue);
		if(!entry) {
			return;
		}

		if(!chipvpn_socket_raw_write(sock, entry)) {
			return;
		}

		chipvpn_socket_dequeue_commit(&sock->tx_queue, entry);
	}
}

void chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue) {
    queue->head = 0;
    queue->tail = 0;
    queue->size = 0;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue) {
    if(queue->size >= queue->total_size) {
    	return NULL;
    }
    return &queue->pool[queue->tail];
}

void chipvpn_socket_enqueue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry) {
    queue->tail = (queue->tail + 1) & (queue->total_size - 1);
    queue->size++;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue) {
    if(queue->size == 0) {
    	return NULL;
    }
    return &queue->pool[queue->head];
}

void chipvpn_socket_dequeue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry) {
    queue->head = (queue->head + 1) & (queue->total_size - 1);
    queue->size--;
}

bool chipvpn_socket_can_enqueue(chipvpn_socket_t *sock) {
	return sock->rx_queue.size < sock->rx_queue.total_size;
}

bool chipvpn_socket_can_dequeue(chipvpn_socket_t *sock) {
	return sock->tx_queue.size > 0;
}

bool chipvpn_socket_can_read(chipvpn_socket_t *sock) {
	return sock->rx_queue.size > 0;
}

bool chipvpn_socket_can_write(chipvpn_socket_t *sock) {
	return sock->tx_queue.size <  sock->tx_queue.total_size;
}

size_t chipvpn_socket_read(chipvpn_socket_t *sock, void *data, size_t size, chipvpn_address_t *addr) {
	chipvpn_socket_vector_t vector[1] = {{
		.data = data,
		.size = size
	}};

	return chipvpn_socket_read_vector(sock, vector, 1, addr);
}

size_t chipvpn_socket_write(chipvpn_socket_t *sock, void *data, size_t size, chipvpn_address_t *addr) {
	chipvpn_socket_vector_t vector[1] = {{
		.data = data,
		.size = size
	}};

	return chipvpn_socket_write_vector(sock, vector, 1, addr);
}

size_t chipvpn_socket_read_vector(chipvpn_socket_t *sock, chipvpn_socket_vector_t *vector, size_t size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&sock->rx_queue);
	if(entry == NULL) {
		return 0;
	}

	if(addr) {
		*addr = entry->addr;
	}

	size_t r = 0;
	for(size_t i = 0; i < size; i++) {
		size_t chunk_size = MIN(vector[i].size, entry->size - r);
		memcpy(vector[i].data, entry->buffer + r, chunk_size);
		r += chunk_size;
	}

	entry->size = 0;

	chipvpn_socket_dequeue_commit(&sock->rx_queue, entry);

	return r;
}

size_t chipvpn_socket_write_vector(chipvpn_socket_t *sock, chipvpn_socket_vector_t *vector, size_t size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->tx_queue);
	if(entry == NULL) {
		return 0;
	}

	if(addr) {
		entry->addr = *addr;
	}

	size_t w = 0;
	for(size_t i = 0; i < size; i++) {
		size_t chunk_size = MIN(vector[i].size, sizeof(entry->buffer) - w);
		memcpy(entry->buffer + w, vector[i].data, chunk_size);
		w += chunk_size;
	}

	entry->size = (uint16_t)w;

	chipvpn_socket_enqueue_commit(&sock->tx_queue, entry);

	return w;
}

void chipvpn_socket_cleanup(chipvpn_socket_t *sock) {
	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	free(sock->tx_queue.pool);
	free(sock->rx_queue.pool);

	chipvpn_secure_zero(sock, sizeof(chipvpn_socket_t));
}