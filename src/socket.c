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
	sock->can_read = 0;
	sock->can_write = 0;
	sock->key_length = 0;

	return sock;
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
	memcpy(sock->key, key, length);
	sock->key_length = length;
}

void chipvpn_socket_preselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_socket_can_read(socket))  FD_CLR(socket->fd, rdset); else FD_SET(socket->fd, rdset);
	if(chipvpn_socket_can_write(socket)) FD_CLR(socket->fd, wdset); else FD_SET(socket->fd, wdset);
	*max = socket->fd;
}

void chipvpn_socket_postselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(socket->fd, rdset)) chipvpn_socket_set_read(socket, true);
	if(FD_ISSET(socket->fd, wdset)) chipvpn_socket_set_write(socket, true);
}

void chipvpn_socket_set_read(chipvpn_socket_t *sock, bool status) {
	sock->can_read = status;
}

void chipvpn_socket_set_write(chipvpn_socket_t *sock, bool status) {
	sock->can_write = status;
}

bool chipvpn_socket_can_read(chipvpn_socket_t *sock) {
	return sock->can_read;
}

bool chipvpn_socket_can_write(chipvpn_socket_t *sock) {
	return sock->can_write;
}

int chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	struct sockaddr_in sa;
	int len = sizeof(sa);

	int r = 0;

	printf("startr\n");

	if(sock->key[0] != 0) {
		char packet[sizeof(uint32_t) + size];

		r = recvfrom(sock->fd, packet, sizeof(packet), 0, (struct sockaddr*)&sa, (socklen_t*)&len);

		r -= sizeof(uint32_t);

		if(r <= 0) {
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
	} else {
		printf("yay\n");
		r = recvfrom(sock->fd, data, size, 0, (struct sockaddr*)&sa, (socklen_t*)&len);
	}

	chipvpn_socket_set_read(sock, false);

	if(addr) {
		addr->ip = sa.sin_addr.s_addr;
		addr->port = ntohs(sa.sin_port);
	}

	return r;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	struct sockaddr_in sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->ip;
	sa.sin_port = htons(addr->port);

	int w = 0;

	printf("startw\n");

	if(sock->key[0] != 0) {

		uint32_t counter = randombytes_random();

		uint32_t state;
		chipvpn_crypto_crc32_init(&state);
		chipvpn_crypto_crc32_update(&state, (unsigned char*)&sock->key, sock->key_length);
		chipvpn_crypto_crc32_update(&state, (unsigned char*)&size, sizeof(size));
		chipvpn_crypto_crc32_update(&state, (unsigned char*)&counter, sizeof(counter));
		uint32_t key = chipvpn_crypto_crc32_final(&state);

		chipvpn_crypto_xor(data, data, size, (char*)&key, sizeof(key));

		uint32_t header = htonl(counter);

		char packet[sizeof(uint32_t) + size];
		memcpy(packet, &header, sizeof(header));
		memcpy(sizeof(uint32_t) + packet, data, size);

		w = sendto(sock->fd, packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa));

		w -= sizeof(uint32_t);

		if(w <= 0) {
			return 0;
		}
	} else {
		printf("yay\n");
		w = sendto(sock->fd, data, size, 0, (struct sockaddr*)&sa, sizeof(sa));
	}

	chipvpn_socket_set_write(sock, false);

	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}