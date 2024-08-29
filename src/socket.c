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
	sock->key_length = 0;
	chipvpn_secure_random((char *)&sock->counter, sizeof(sock->counter));

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

void chipvpn_socket_set_key(chipvpn_socket_t *sock, const char *key, int length) {
	memset(sock->key, 0, sizeof(sock->key));
	memcpy(sock->key, key, length);
	sock->key_length = length;
}

void chipvpn_socket_preselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset, int *max) {
	if(!chipvpn_socket_can_enqueue(socket))  FD_CLR(socket->fd, rdset); else FD_SET(socket->fd, rdset);
	if(!chipvpn_socket_can_dequeue(socket))  FD_CLR(socket->fd, wdset); else FD_SET(socket->fd, wdset);
	*max = socket->fd;
}

void chipvpn_socket_postselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(socket->fd, rdset)) {
		struct sockaddr_in sa;
		int len = sizeof(sa);

		char buffer[sizeof(chipvpn_packet_header_t) + SOCKET_QUEUE_ENTRY_SIZE];

		int r = recvfrom(socket->fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
		if(r <= 0) {
			return;
		}

		chipvpn_socket_packet_t *header  = buffer;
		uint16_t fragment_id             = ntohs(header->id);
		uint16_t fragment_offset         = ntohs(header->offset);
		uint16_t fragment_total          = ntohs(header->total);
		uint16_t fragment_size           = r - sizeof(chipvpn_socket_packet_t);

		chipvpn_socket_queue_entry_t *entry = NULL;

		for(chipvpn_list_node_t *g = chipvpn_list_begin(&socket->rx_queue.queue); g != chipvpn_list_end(&socket->rx_queue.queue); g = chipvpn_list_next(g)) {
			chipvpn_socket_queue_entry_t *current = (chipvpn_socket_queue_entry_t*)g;

			if(current->is_used == true && current->id == fragment_id) {
				entry = current;
				break;
			}
		}

		if(entry == NULL) {
			entry = chipvpn_socket_enqueue_acquire(&socket->rx_queue);
			if(!entry) {
				return;
			}
			entry->id = 0;
			entry->size = 0;
			entry->total = 0;
			chipvpn_socket_enqueue_commit(&socket->rx_queue, entry);
		}

		memcpy(entry->buffer + fragment_offset, sizeof(chipvpn_socket_packet_t) + buffer, fragment_size);
		//entry->size = r;
		entry->id = fragment_id;
		entry->total = fragment_total;
		entry->size += fragment_size;

		entry->addr.ip = sa.sin_addr.s_addr;
		entry->addr.port = ntohs(sa.sin_port);
	}
	if(FD_ISSET(socket->fd, wdset)) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&socket->tx_queue);
		if(!entry) {
			return;
		}

		struct sockaddr_in sa; 
	
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = entry->addr.ip;
		sa.sin_port = htons(entry->addr.port);

		int fragment_size = MIN(entry->size, 1400);

		char buffer[sizeof(chipvpn_socket_packet_t) + SOCKET_QUEUE_ENTRY_SIZE];

		chipvpn_socket_packet_t *header = (chipvpn_socket_packet_t*)&buffer;
		header->id     = htons(entry->id);
		header->offset = htons(entry->total - entry->size);
		header->total  = htons(entry->total);

		memcpy(buffer + sizeof(chipvpn_socket_packet_t), entry->buffer + (entry->total - entry->size), fragment_size);

		int w = sendto(socket->fd, buffer, sizeof(chipvpn_socket_packet_t) + fragment_size, 0, (struct sockaddr*)&sa, sizeof(sa));
		if(w <= 0) {
			return;
		}

		entry->size -= fragment_size;

		if(entry->size == 0) {
			chipvpn_socket_dequeue_commit(entry);
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
	// int j = 0;
	// for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
	// 	chipvpn_socket_queue_entry_t *current = &queue->pool[i];
	// 	if(current->is_used) {
	// 		++j;
	// 	}
	// }
	// return j;

	return (int)chipvpn_list_size(&queue->queue);
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
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)chipvpn_list_begin(&queue->queue);
		return entry;
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

chipvpn_socket_queue_entry_t *chipvpn_socket_available_entry(chipvpn_socket_queue_t *queue) {
	for(chipvpn_list_node_t *g = chipvpn_list_previous(chipvpn_list_end(&queue->queue)); g != chipvpn_list_end(&queue->queue); g = chipvpn_list_previous(g)) {
		chipvpn_socket_queue_entry_t *entry = (chipvpn_socket_queue_entry_t*)g;

		if(entry->is_used && entry->size == entry->total && entry->size != 0) {
			return entry;
		}
	}

	return NULL;
}

bool chipvpn_socket_can_enqueue(chipvpn_socket_t *sock) {
	if(chipvpn_socket_queue_size(&sock->rx_queue) >= SOCKET_QUEUE_SIZE - 1) {
		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_dequeue_acquire(&sock->rx_queue);
		if(entry) {
			chipvpn_socket_dequeue_commit(entry);
		}
	}

	return true;
}

bool chipvpn_socket_can_dequeue(chipvpn_socket_t *sock) {
	return chipvpn_socket_queue_size(&sock->tx_queue) > 0;
}

bool chipvpn_socket_can_read(chipvpn_socket_t *sock) {
	return chipvpn_socket_available_entry(&sock->rx_queue) != NULL;
}

bool chipvpn_socket_can_write(chipvpn_socket_t *sock) {
	return chipvpn_socket_queue_size(&sock->tx_queue) < SOCKET_QUEUE_SIZE;
}

int chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_available_entry(&sock->rx_queue);
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
	entry->id = rand() % 0xFFFF;
	entry->size = w;
	entry->total = w;

	chipvpn_socket_enqueue_commit(&sock->tx_queue, entry);

	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}