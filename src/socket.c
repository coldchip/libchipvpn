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
		chipvpn_socket_fragment_packet buf;

		struct sockaddr_in sa;
		int len = sizeof(sa);

		int r = recvfrom(socket->fd, &buf, sizeof(buf), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
		if(r <= 0) {
			return;
		}

		chipvpn_address_t addr;
		addr.ip = sa.sin_addr.s_addr;
		addr.port = ntohs(sa.sin_port);

		chipvpn_socket_fragment_enqueue_acquire(&socket->rx_queue, ntohs(buf.id), buf.index, buf.total, buf.buffer, r - 4, &addr);
	}
	if(FD_ISSET(socket->fd, wdset)) {
		chipvpn_socket_fragment_packet buf;
		uint16_t id, size;
		uint8_t index, total;
		chipvpn_address_t addr;

		chipvpn_socket_fragment_dequeue_acquire(&socket->tx_queue, &id, &index, &total, buf.buffer, &size, &addr);

		buf.id  = htons(id);
		buf.index = index;
		buf.total = total;

		struct sockaddr_in sa;
	
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = addr.ip;
		sa.sin_port = htons(addr.port);

		int w = sendto(socket->fd, &buf, size + 4, 0, (struct sockaddr*)&sa, sizeof(sa));
		if(w <= 0) {
			return;
		}
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

chipvpn_socket_queue_entry_t *chipvpn_socket_get_entry(chipvpn_socket_queue_t *queue, uint16_t id) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&queue->queue); p != chipvpn_list_end(&queue->queue); p = chipvpn_list_next(p)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)p;
		if(entry->id == id) {
			return entry;
		}
	}
	return false;
}

void chipvpn_socket_fragment_enqueue_acquire(chipvpn_socket_queue_t *queue, uint32_t id, uint8_t index, uint8_t total, char *buf, uint16_t size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_get_entry(queue, id);
	if(!entry) {
		if(chipvpn_list_size(&queue->queue) > SOCKET_QUEUE_SIZE) {
			chipvpn_socket_dequeue_commit(chipvpn_list_front(&queue->queue));
		}

		entry = chipvpn_socket_enqueue_acquire(queue);
		entry->map = 0;
		entry->id = id;
		entry->addr = *addr;
		chipvpn_socket_enqueue_commit(queue, entry);
	}

	memcpy(entry->buffer + (index * 64), buf, size);
	entry->size += size;
	entry->total = total;

	entry->map |= 1 << index;
}

void chipvpn_socket_fragment_dequeue_acquire(chipvpn_socket_queue_t *queue, uint16_t *id, uint8_t *index, uint8_t *total, char *buf, uint16_t *size, chipvpn_address_t *addr) {
	if(!chipvpn_list_empty(&queue->queue)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)chipvpn_list_front(&queue->queue);
		
		uint32_t i = 0;
		uint32_t map = entry->map;
		while((map > 0) && (map & 0x1) == 0) {
			map = map >> 1;
			i++;
		}

		*id = entry->id;
		*addr = entry->addr;
		*index = i;
		*size = MIN(64, entry->size - ((entry->map - 1) * 64));
		*total = (entry->size / 64) + 1;

		memcpy(buf, entry->buffer + (i * 64), *size);

		entry->map = entry->map >> 1;

		if(entry->map == 0) {
			chipvpn_socket_dequeue_commit(entry);
		}
	}
	return NULL;
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
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&queue->queue); p != chipvpn_list_end(&queue->queue); p = chipvpn_list_next(p)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)p;

		uint32_t mask = 1 << entry->total;

		if((entry->map) + 1 == mask) {
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
	return chipvpn_socket_dequeue_acquire(&sock->rx_queue) != NULL;
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

	chipvpn_socket_dequeue_commit(entry);

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

	entry->id = rand() % 0xFFFF;
	entry->map = (entry->size / 64) + 1;

	chipvpn_socket_enqueue_commit(&sock->tx_queue, entry);

	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);

	chipvpn_socket_reset_queue(&sock->tx_queue);
	chipvpn_socket_reset_queue(&sock->rx_queue);

	free(sock);
}