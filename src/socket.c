#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include "socket.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include "packet.h"
#include "chipvpn.h"
#include "util.h"

chipvpn_socket_t *chipvpn_socket_create(int family) {
	chipvpn_socket_t *sock = malloc(sizeof(chipvpn_socket_t));
	if(!sock) {
		return NULL;
	}

	int fd = socket(family, SOCK_DGRAM, 0);
	if(fd < 0) {
		return NULL;
	}

	sock->fd = fd;
	sock->family = family;

	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	return sock;
}

bool chipvpn_socket_set_sendbuf(chipvpn_socket_t *sock, int size) {
	if(setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0) {
		return false;
	}
	return true;
}

bool chipvpn_socket_set_recvbuf(chipvpn_socket_t *sock, int size) {
	if(setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
		return false;
	}
	return true;
}

bool chipvpn_socket_bind(chipvpn_socket_t *sock, chipvpn_address_t *addr) {
	struct sockaddr_storage sa = {0};
	socklen_t len = 0;

	switch(sock->family) {
		case AF_INET: {
			struct sockaddr_in *sa_inet = (struct sockaddr_in *)&sa;
			sa_inet->sin_family = AF_INET;
			sa_inet->sin_addr.s_addr = addr->ip;
			sa_inet->sin_port = htons(addr->port);
			len = sizeof(*sa_inet);
		} 
		break;
		case AF_UNIX: {
			struct sockaddr_un *sa_unix = (struct sockaddr_un *)&sa;
			sa_unix->sun_family = AF_UNIX;
			memcpy(sa_unix->sun_path, addr->path, sizeof(addr->path));
			len = sizeof(*sa_unix);

			unlink(addr->path);
		} 
		break;
	}

	if(bind(sock->fd, (struct sockaddr *)&sa, len) < 0) {
		return false;
	}
	
	return true;
}

void chipvpn_socket_preselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset, int *max) {
	if(!chipvpn_socket_can_enqueue(sock))  FD_CLR(sock->fd, rdset); else FD_SET(sock->fd, rdset);
	if(!chipvpn_socket_can_dequeue(sock))  FD_CLR(sock->fd, wdset); else FD_SET(sock->fd, wdset);
	*max = sock->fd;
}

void chipvpn_socket_postselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(sock->fd, rdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->rx_queue);
		if(!entry) {
			return;
		}

		struct sockaddr_storage sa;
		socklen_t len = sizeof(sa);

		int r = recvfrom(sock->fd, entry->buffer, sizeof(entry->buffer), 0, (struct sockaddr*)&sa, &len);
		if(r <= 0) {
			return;
		}

		switch(sock->family) {
			case AF_INET: {
				struct sockaddr_in *sa_inet = (struct sockaddr_in *)&sa;
				entry->addr.ip = sa_inet->sin_addr.s_addr;
				entry->addr.port = ntohs(sa_inet->sin_port);
			}
			break;
			case AF_UNIX: {
				struct sockaddr_un *sa_unix = (struct sockaddr_un *)&sa;
				memcpy(entry->addr.path, sa_unix->sun_path, sizeof(entry->addr.path));
			}
			break;
		}

		entry->size = r;
		chipvpn_socket_enqueue_commit(&sock->rx_queue, entry);
		
	}
	if(FD_ISSET(sock->fd, wdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&sock->tx_queue);
		if(!entry) {
			return;
		}

		struct sockaddr_storage sa = {0};
		socklen_t len = 0;

		switch(sock->family) {
			case AF_INET: {
				struct sockaddr_in *sa_inet = (struct sockaddr_in *)&sa;
				sa_inet->sin_family = AF_INET;
				sa_inet->sin_addr.s_addr = entry->addr.ip;
				sa_inet->sin_port = htons(entry->addr.port);
				len = sizeof(*sa_inet);
			} 
			break;
			case AF_UNIX: {
				struct sockaddr_un *sa_unix = (struct sockaddr_un *)&sa;
				sa_unix->sun_family = AF_UNIX;
				memcpy(sa_unix->sun_path, entry->addr.path, sizeof(entry->addr.path));
				len = sizeof(*sa_unix);
			} 
			break;
		}

		int w = sendto(sock->fd, entry->buffer, entry->size, 0, (struct sockaddr*)&sa, len);
		if(w <= 0) {
			return;
		}

		entry->size = 0;
		chipvpn_socket_dequeue_commit(&sock->tx_queue, entry);
	}
}

void chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue) {
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		current->is_used = false;
	}

	queue->size = 0;

	chipvpn_list_clear(&queue->queue);
}

int chipvpn_socket_queue_size(chipvpn_socket_queue_t *queue) {
	return queue->size;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue) {
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		if(!current->is_used) {
			return current;
		}
	}
	return NULL;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue) {
	if(!chipvpn_list_empty(&queue->queue)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)chipvpn_list_front(&queue->queue);
		return entry;
	}
	return NULL;
}

void chipvpn_socket_enqueue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry) {
	entry->is_used = true;
	chipvpn_list_insert(chipvpn_list_end(&queue->queue), entry);
	queue->size++;
}

void chipvpn_socket_dequeue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry) {
	queue->size--;
	chipvpn_list_remove(&entry->node);
	entry->is_used = false;
}

bool chipvpn_socket_can_enqueue(chipvpn_socket_t *sock) {
	return chipvpn_socket_queue_size(&sock->rx_queue) < SOCKET_QUEUE_SIZE;
}

bool chipvpn_socket_can_dequeue(chipvpn_socket_t *sock) {
	return chipvpn_socket_queue_size(&sock->tx_queue) > 0;
}

bool chipvpn_socket_can_read(chipvpn_socket_t *sock) {
	return chipvpn_socket_queue_size(&sock->rx_queue) > 0;
}

bool chipvpn_socket_can_write(chipvpn_socket_t *sock) {
	return chipvpn_socket_queue_size(&sock->tx_queue) < SOCKET_QUEUE_SIZE;
}

int chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&sock->rx_queue);
	if(entry == NULL) {
		return 0;
	}

	int r = MIN(size, entry->size);
	if(r <= 0) {
		return 0;
	}

	if(addr) {
		*addr = entry->addr;
	}

	memcpy(data, entry->buffer, r);
	entry->size = 0;

	chipvpn_socket_dequeue_commit(&sock->rx_queue, entry);

	return r;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->tx_queue);
	if(entry == NULL) {
		return 0;
	}

	int w = MIN(size, sizeof(entry->buffer));
	if(w <= 0) {
		return 0;
	}

	if(addr) {
		entry->addr = *addr;
	}

	memcpy(entry->buffer, data, w);
	entry->size = w;

	chipvpn_socket_enqueue_commit(&sock->tx_queue, entry);

	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);

	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	free(sock);
}