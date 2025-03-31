#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include "socket.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "crypto.h"
#include "packet.h"
#include "chipvpn.h"
#include "util.h"

chipvpn_socket_t *chipvpn_socket_create() {
	chipvpn_socket_t *sock = malloc(sizeof(chipvpn_socket_t));
	if(!sock) {
		return NULL;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		return NULL;
	}

	sock->fd = fd;

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
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->ip;
	sa.sin_port = htons(addr->port);

	if(bind(sock->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		return false;
	}
	return true;
}

void chipvpn_socket_preselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset, int *max) {
	if(!chipvpn_socket_can_enqueue(socket))  FD_CLR(socket->fd, rdset); else FD_SET(socket->fd, rdset);
	if(!chipvpn_socket_can_dequeue(socket))  FD_CLR(socket->fd, wdset); else FD_SET(socket->fd, wdset);
	*max = socket->fd;
}

void chipvpn_socket_postselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(socket->fd, rdset)) {
		chipvpn_socket_fragment_entry_t *fragment = malloc(sizeof(chipvpn_socket_fragment_entry_t));

		struct sockaddr_in sa;
		int len = sizeof(sa);

		int r = recvfrom(socket->fd, fragment, sizeof(chipvpn_socket_fragment_entry_t), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
		if(r <= 0) {
			return;
		}

		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&socket->rx_queue, fragment->id);
		if(!entry) {
			return;
		}

		entry->count = fragment->count;

		chipvpn_list_insert(chipvpn_list_end(&entry->fragment), fragment);

		entry->size += fragment->size;

		entry->addr.ip = sa.sin_addr.s_addr;
		entry->addr.port = ntohs(sa.sin_port);

	}
	if(FD_ISSET(socket->fd, wdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&socket->tx_queue);
		if(!entry) {
			return;
		}

		if(!chipvpn_list_empty(&entry->fragment)) {
			chipvpn_socket_fragment_entry_t *fragment = (chipvpn_socket_fragment_entry_t*)chipvpn_list_front(&entry->fragment);
			
			struct sockaddr_in sa;

			memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			sa.sin_addr.s_addr = entry->addr.ip;
			sa.sin_port = htons(entry->addr.port);

			int w = sendto(socket->fd, fragment, sizeof(chipvpn_socket_fragment_entry_t), 0, (struct sockaddr*)&sa, sizeof(sa));
			if(w <= 0) {
				return;
			}

			chipvpn_list_remove(&fragment->node);
			free(fragment);

			entry->count--;

			return;
		}

		chipvpn_socket_dequeue_commit(entry);
	}
}

void chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue) {
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *entry = &queue->pool[i];
		chipvpn_list_clear(&entry->fragment);
		entry->is_used = false;
	}
	chipvpn_list_clear(&queue->queue);
}

int chipvpn_socket_queue_size(chipvpn_socket_queue_t *queue) {
	return (int)chipvpn_list_size(&queue->queue);
}

chipvpn_socket_queue_entry_t *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue, uint16_t id) {
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		if(current->id == id) {
			return current;
		}
	}

	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		if(!current->is_used) {
			current->id = id;
			current->count = 0;
			chipvpn_socket_enqueue_commit(queue, current);
			return current;
		}
	}

	chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)chipvpn_list_front(&queue->queue);
	entry->id = id;
	entry->count = 0;
	while(!chipvpn_list_empty(&entry->fragment)) {
		chipvpn_socket_fragment_entry_t *fragment = (chipvpn_socket_fragment_entry_t*)chipvpn_list_remove(chipvpn_list_begin(&entry->fragment));
		free(fragment);
	}

	return entry;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&queue->queue); p != chipvpn_list_end(&queue->queue); p = chipvpn_list_next(p)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)p;
		if(chipvpn_list_size(&entry->fragment) == entry->count) {
			return entry;			
		}
	}

	return NULL;
}

void chipvpn_socket_enqueue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry) {
	entry->is_used = true;
	chipvpn_list_insert(chipvpn_list_end(&queue->queue), entry);
}

void chipvpn_socket_dequeue_commit(chipvpn_socket_queue_entry_t *entry) {
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

	uint16_t processed = 0;

	while(!chipvpn_list_empty(&entry->fragment)) {
		chipvpn_socket_fragment_entry_t *fragment = (chipvpn_socket_fragment_entry_t*)chipvpn_list_remove(chipvpn_list_begin(&entry->fragment));

		int r = MIN(size, entry->size);
		if(r <= 0) {
			return 0;
		}

		if(addr) {
			*addr = entry->addr;
		}

		memcpy(data + fragment->offset, fragment->buffer, fragment->size);

		free(fragment);

		processed += fragment->size;
	}

	chipvpn_socket_dequeue_commit(entry);

	return processed;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	uint16_t fragment_id    = rand() % 0xFFFF;
	uint16_t fragment_count = (size / SOCKET_FRAGMENT_ENTRY_SIZE) + 1;

	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->tx_queue, fragment_id);
	if(entry == NULL) {
		return 0;
	}

	uint16_t processed = 0;

	for(int i = 0; i < fragment_count; i++) {
		chipvpn_socket_fragment_entry_t *fragment = malloc(sizeof(chipvpn_socket_fragment_entry_t));

		int w = MIN(size - processed, sizeof(fragment->buffer));
		if(w <= 0) {
			return 0;
		}

		if(addr) {
			entry->addr = *addr;
		}

		memcpy(fragment->buffer, ((char*)data) + processed, w);
		fragment->id     = fragment_id;
		fragment->offset = processed;
		fragment->size   = w;
		fragment->count  = fragment_count;

		entry->count++;

		chipvpn_list_insert(chipvpn_list_end(&entry->fragment), fragment);

		processed += w;
	}

	return processed;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);

	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	free(sock);
}