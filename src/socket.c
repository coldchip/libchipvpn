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

	crypto_hash_sha256((unsigned char*)sock->crypto.key, (unsigned char*)key, length);
	memset(sock->crypto.nonce, 0, sizeof(sock->crypto.nonce));
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

	int r = recvfrom(sock->fd, data, size, 0, (struct sockaddr*)&sa, (socklen_t*)&len);
	chipvpn_socket_set_read(sock, false);

	if(addr) {
		addr->ip = sa.sin_addr.s_addr;
		addr->port = ntohs(sa.sin_port);
	}

	if(r > 0 && sock->key_length > 0) {
		if(size > sizeof(chipvpn_packet_header_t)) {
			chipvpn_packet_header_t h = *(chipvpn_packet_header_t*)data;
			chipvpn_crypto_xchacha20(&sock->crypto, (char*)&h, sizeof(chipvpn_packet_header_t), 1024);
			
			int dr = 0;

			switch(h.type) {
				case CHIPVPN_PACKET_AUTH: {
					dr = sizeof(chipvpn_packet_auth_t);
				}
				break;
				case CHIPVPN_PACKET_DATA: {
					dr = sizeof(chipvpn_packet_data_t);
				}
				break;
				case CHIPVPN_PACKET_PING: {
					dr = sizeof(chipvpn_packet_ping_t);
				}
				break;
			}

			chipvpn_crypto_xchacha20(&sock->crypto, data, MIN(dr, size), 1024);
		}
	}

	return r;
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	struct sockaddr_in sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->ip;
	sa.sin_port = htons(addr->port);

	if(size > 0 && sock->key_length > 0) {
		if(size > sizeof(chipvpn_packet_header_t)) {
			chipvpn_packet_header_t h = *(chipvpn_packet_header_t*)data;
			
			int dw = 0;
			switch(h.type) {
				case CHIPVPN_PACKET_AUTH: {
					dw = sizeof(chipvpn_packet_auth_t);
				}
				break;
				case CHIPVPN_PACKET_DATA: {
					dw = sizeof(chipvpn_packet_data_t);
				}
				break;
				case CHIPVPN_PACKET_PING: {
					dw = sizeof(chipvpn_packet_ping_t);
				}
				break;
			}


			chipvpn_crypto_xchacha20(&sock->crypto, data, MAX(dw, size), 1024);
		}
	}

	int w = sendto(sock->fd, data, size, 0, (struct sockaddr*)&sa, sizeof(sa));
	chipvpn_socket_set_write(sock, false);
	
	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}