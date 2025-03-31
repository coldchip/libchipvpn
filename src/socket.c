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
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&socket->rx_queue);

		struct sockaddr_in sa;
		int len = sizeof(sa);

		int r = recvfrom(socket->fd, &entry->fragment, sizeof(entry->fragment), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
		if(r <= 0) {
			return;
		}

		entry->size = r - 6;

		entry->addr.ip = sa.sin_addr.s_addr;
		entry->addr.port = ntohs(sa.sin_port);

		chipvpn_socket_enqueue_commit(&socket->rx_queue, entry);
		
	}
	if(FD_ISSET(socket->fd, wdset)) {
		uint16_t count = 0;

		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&socket->tx_queue);
		if(!entry) {
			return;
		}

		struct sockaddr_in sa;
	
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = entry->addr.ip;
		sa.sin_port = htons(entry->addr.port);

		int w = sendto(socket->fd, &entry->fragment, entry->size + 6, 0, (struct sockaddr*)&sa, sizeof(sa));
		if(w <= 0) {
			return;
		}

		chipvpn_socket_dequeue_commit(entry);
	}
}

void chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue) {
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		current->is_used = false;
	}

	chipvpn_list_clear(&queue->queue);
}

int chipvpn_socket_queue_size(chipvpn_socket_queue_t *queue) {
	return (int)chipvpn_list_size(&queue->queue);
}

chipvpn_socket_queue_entry_t *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue) {
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		if(!current->is_used) {
			return current;
		}
	}

	chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)chipvpn_list_back(&queue->queue);
	chipvpn_socket_dequeue_commit(entry);

	return entry;
}

chipvpn_socket_queue_entry_t **chipvpn_socket_enqueue_acquire_fragment(chipvpn_socket_queue_t *queue, uint16_t size, uint16_t *count) {
	static chipvpn_socket_queue_entry_t *result[32];

	uint16_t fragment_id = rand() & 0xFFFF;
	uint8_t  fragments   = (size / 32) + 1;

	for(int i = 0; i < fragments; i++) {
		chipvpn_socket_queue_entry_t *current = chipvpn_socket_enqueue_acquire(queue);
		if(current == NULL) {
			return NULL;
		}

		current->is_used = true;

		result[i] = current;
	}

	for(int i = 0; i < fragments; i++) {
		result[i]->fragment.id = fragment_id;
		result[i]->is_used = false;
	}

	*count = fragments;

	return result;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue) {
	if(!chipvpn_list_empty(&queue->queue)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)chipvpn_list_front(&queue->queue);
		return entry;
	}

	return NULL;
}

chipvpn_socket_queue_entry_t *chipvpn_socket_dequeue_acquire_fragment(chipvpn_socket_queue_t *queue, uint16_t size, uint16_t *count) {
	static chipvpn_socket_queue_entry_t *result[32];

	for(chipvpn_list_node_t *q = chipvpn_list_begin(&queue->queue); q != chipvpn_list_end(&queue->queue); q = chipvpn_list_next(q)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)q;

		uint16_t head_fragment_id = entry->fragment.id;
		uint16_t head_fragment_size = entry->fragment.size;

		uint16_t x = 0;
		uint16_t y = 0;

		for(chipvpn_list_node_t *q1 = entry; q1 != chipvpn_list_end(&queue->queue); q1 = chipvpn_list_next(q1)) {
			chipvpn_socket_queue_entry_t *needle = (chipvpn_socket_queue_entry_t*)q1;
			
			if(entry->fragment.id == needle->fragment.id) {
				x += needle->size;
				result[y] = needle;
				y++;
			}
		}

		if(x == head_fragment_size) {
			*count = y;
			return result;
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
	uint16_t count = 0;

	chipvpn_socket_queue_entry_t **entries = chipvpn_socket_dequeue_acquire_fragment(&sock->rx_queue, 0, &count);
	if(entries == NULL) {
		return 0;
	}

	int processed = 0;

	for(int i = 0; i < count; i++) {
		int r = MIN(size, entries[i]->size);
		if(r <= 0) {
			return 0;
		}

		if(addr) {
			*addr = entries[i]->addr;
		}

		// printf("%i %i\n", entries[i]->fragment.offset, r);

		memcpy(data + entries[i]->fragment.offset, entries[i]->fragment.buffer, r);
		entries[i]->fragment.size = 0;

		chipvpn_socket_dequeue_commit(entries[i]);

		processed += r;
	}

	return processed;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	uint16_t count = 0;

	chipvpn_socket_queue_entry_t **entries = chipvpn_socket_enqueue_acquire_fragment(&sock->tx_queue, size, &count);
	if(entries == NULL) {
		return 0;
	}

	int processed = 0;

	for(int i = 0; i < count; i++) {
		int w = MIN(size - processed, sizeof(entries[i]->fragment.buffer));
		if(w <= 0) {
			return 0;
		}

		if(addr) {
			entries[i]->addr = *addr;
		}

		// printf("COPY frag %i, index %i, size %i\n", i, processed, w);

		memcpy(entries[i]->fragment.buffer, data + processed, w);
		entries[i]->fragment.size   = size;
		entries[i]->fragment.offset = processed;
		entries[i]->size            = w;
	
		chipvpn_socket_enqueue_commit(&sock->tx_queue, entries[i]);

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