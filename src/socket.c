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

		chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&socket->rx_queue);
		if(!entry) {
			return;
		}

		int r = recvfrom(socket->fd, entry->buffer, sizeof(entry->buffer), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
		if(r <= 0) {
			return;
		}

		entry->size = r;

		entry->addr.ip = sa.sin_addr.s_addr;
		entry->addr.port = ntohs(sa.sin_port);

		chipvpn_socket_enqueue_commit(&socket->rx_queue, entry);
		
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

		int w = sendto(socket->fd, entry->buffer, entry->size, 0, (struct sockaddr*)&sa, sizeof(sa));
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
	int j = 0;
	for(int i = 0; i < SOCKET_QUEUE_SIZE; i++) {
		chipvpn_socket_queue_entry_t *current = &queue->pool[i];
		if(current->is_used) {
			++j;
		}
	}
	return j;
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

	int r = entry->size;
	r -= sizeof(uint32_t);
	if(r <= 0) {
		return 0;
	}

	if(addr) {
		*addr = entry->addr;
	}

	uint32_t counter = ntohl(*(uint32_t*)entry->buffer);
	char    *buf     = entry->buffer + sizeof(uint32_t);

	uint32_t state;
	chipvpn_crypto_crc32_init(&state);
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&sock->key, sock->key_length);
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&r, sizeof(r));
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&counter, sizeof(counter));
	uint32_t key = chipvpn_crypto_crc32_final(&state);

	chipvpn_crypto_xor(data, buf, r, (char*)&key, sizeof(key));

	chipvpn_socket_dequeue_commit(entry);

	return r;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_entry_t *entry = chipvpn_socket_enqueue_acquire(&sock->tx_queue);
	if(entry == NULL) {
		return 0;
	}

	entry->size = sizeof(uint32_t) + size;
	int w = entry->size;
	w -= sizeof(uint32_t);
	if(w <= 0) {
		return 0;
	}

	if(addr) {
		entry->addr = *addr;
	}

	uint32_t state0;
	chipvpn_crypto_crc32_update(&state0, (unsigned char*)&sock->key, sock->key_length);
	chipvpn_crypto_crc32_update(&state0, (unsigned char*)&sock->counter, sizeof(sock->counter));
	sock->counter = chipvpn_crypto_crc32_final(&state0);

	uint32_t state;
	chipvpn_crypto_crc32_init(&state);
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&sock->key, sock->key_length);
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&size, sizeof(size));
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&sock->counter, sizeof(sock->counter));
	uint32_t key = chipvpn_crypto_crc32_final(&state);

	chipvpn_crypto_xor(data, data, size, (char*)&key, sizeof(key));

	uint32_t header = htonl(sock->counter);

	memcpy(entry->buffer, &header, sizeof(header));
	memcpy(sizeof(uint32_t) + entry->buffer, data, size);

	chipvpn_socket_enqueue_commit(&sock->tx_queue, entry);

	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}