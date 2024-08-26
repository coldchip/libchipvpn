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
	sock->tx_size = 0;
	sock->rx_size = 0;
	sock->key_length = 0;
	chipvpn_secure_random((char *)&sock->counter, sizeof(sock->counter));

	chipvpn_list_clear(&sock->tx_queue);
	chipvpn_list_clear(&sock->rx_queue);

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

		chipvpn_socket_queue_t *queue = malloc(sizeof(chipvpn_socket_queue_t));

		int r = recvfrom(socket->fd, queue->buffer, sizeof(queue->buffer), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
		queue->size = r;

		queue->addr.ip = sa.sin_addr.s_addr;
		queue->addr.port = ntohs(sa.sin_port);
		chipvpn_list_insert(chipvpn_list_end(&socket->rx_queue), queue);
	}
	if(FD_ISSET(socket->fd, wdset)) {
		chipvpn_socket_queue_t *queue = (chipvpn_socket_queue_t*)chipvpn_list_remove(chipvpn_list_begin(&socket->tx_queue));
		struct sockaddr_in sa;
	
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = queue->addr.ip;
		sa.sin_port = htons(queue->addr.port);

		int w = sendto(socket->fd, queue->buffer, queue->size, 0, (struct sockaddr*)&sa, sizeof(sa));
	
		free(queue);
	}
}

bool chipvpn_socket_can_enqueue(chipvpn_socket_t *sock) {
	return chipvpn_list_size(&sock->rx_queue) < 100;
}

bool chipvpn_socket_can_dequeue(chipvpn_socket_t *sock) {
	return chipvpn_list_size(&sock->tx_queue) > 0;
}

bool chipvpn_socket_can_read(chipvpn_socket_t *sock) {
	return chipvpn_list_size(&sock->rx_queue) > 0;
}

bool chipvpn_socket_can_write(chipvpn_socket_t *sock) {
	return chipvpn_list_size(&sock->tx_queue) < 100;
}

int chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	chipvpn_socket_queue_t *queue = (chipvpn_socket_queue_t*)chipvpn_list_remove(chipvpn_list_begin(&sock->rx_queue));

	char *packet = queue->buffer;
	int r = queue->size;

	r -= sizeof(uint32_t);

	if(r <= 0) {
		free(queue);
		return 0;
	}

	uint32_t counter = ntohl(*(uint32_t*)packet);
	char    *buf     = packet + sizeof(uint32_t);

	uint32_t state;
	chipvpn_crypto_crc32_init(&state);
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&sock->key, sock->key_length);
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&r, sizeof(r));
	chipvpn_crypto_crc32_update(&state, (unsigned char*)&counter, sizeof(counter));
	uint32_t key = chipvpn_crypto_crc32_final(&state);

	chipvpn_crypto_xor(data, buf, r, (char*)&key, sizeof(key));

	if(addr) {
		*addr = queue->addr;
	}

	free(queue);
	return r;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
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

	// char *packet = sock->tx_buffer;
	chipvpn_socket_queue_t *queue = malloc(sizeof(chipvpn_socket_queue_t));
	char *packet = queue->buffer;
	memcpy(packet, &header, sizeof(header));
	memcpy(sizeof(uint32_t) + packet, data, size);

	int w = sizeof(uint32_t) + size;
	//chipvpn_socket_set_write(sock, w);
	queue->size = w;
	queue->addr = *addr;
	chipvpn_list_insert(chipvpn_list_end(&sock->tx_queue), queue);

	w -= sizeof(uint32_t);

	if(w <= 0) {
		return 0;
	}

	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}