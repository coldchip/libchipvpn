#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include "socket.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "packet.h"
#include "chipvpn.h"
#include "util.h"

chipvpn_socket_t *chipvpn_socket_create(int rfd, int wfd, int type) {
	chipvpn_socket_t *sock = malloc(sizeof(chipvpn_socket_t));
	if(!sock) {
		return NULL;
	}

	sock->rfd = rfd;
	sock->wfd = wfd;
	sock->type = type;

	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	return sock;
}

void chipvpn_socket_preselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_socket_can_enqueue(sock)) FD_SET(sock->rfd, rdset); else FD_CLR(sock->rfd, rdset);
	if(chipvpn_socket_can_dequeue(sock)) FD_SET(sock->wfd, wdset); else FD_CLR(sock->wfd, wdset);
	*max = MAX(sock->rfd, sock->wfd);
}

void chipvpn_socket_postselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(sock->rfd, rdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->rx_queue);
		if(!entry) {
			return;
		}

		if(sock->type == CHIPVPN_SOCKET_DGRAM) {
			struct sockaddr_in sa;
			int len = sizeof(sa);

			int r = recvfrom(sock->rfd, entry->buffer, sizeof(entry->buffer), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
			if(r <= 0) {
				return;
			}

			entry->size = r;

			entry->addr.ip = sa.sin_addr.s_addr;
			entry->addr.port = ntohs(sa.sin_port);
		} else {
			int r = read(sock->rfd, entry->buffer, sizeof(entry->buffer));
			if(r <= 0) {
				return;
			}

			entry->size = r;
		}

		chipvpn_socket_enqueue_commit(&sock->rx_queue, entry);
		
	}
	if(FD_ISSET(sock->wfd, wdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&sock->tx_queue);
		if(!entry) {
			return;
		}

		if(sock->type == CHIPVPN_SOCKET_DGRAM) {
			struct sockaddr_in sa = {
				.sin_family = AF_INET,
				.sin_addr.s_addr = entry->addr.ip,
				.sin_port = htons(entry->addr.port)
			};
			
			int w = sendto(sock->wfd, entry->buffer, entry->size, 0, (struct sockaddr*)&sa, sizeof(sa));
			if(w <= 0) {
				return;
			}
		} else {
			int w = write(sock->wfd, entry->buffer, entry->size);
			if(w <= 0) {
				return;
			}
		}
	
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
	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	free(sock);
}