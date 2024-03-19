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

	char p[sizeof(int) + size];

	int r = recvfrom(sock->fd, p, sizeof(p), 0, (struct sockaddr*)&sa, (socklen_t*)&len);
	chipvpn_socket_set_read(sock, false);

	if(r <= sizeof(int)) {
		return 0;
	}

	int a = 0;

	memcpy(&a, p, sizeof(int));
	memcpy(data, sizeof(int) + p, r - sizeof(int));
	chipvpn_crypto_xchacha20(&sock->crypto, data, r - sizeof(int), ntohl(a));

	if(addr) {
		addr->ip = sa.sin_addr.s_addr;
		addr->port = ntohs(sa.sin_port);
	}

	return r - sizeof(int);
}

int chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	struct sockaddr_in sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->ip;
	sa.sin_port = htons(addr->port);

	int r = randombytes_random();

	chipvpn_crypto_xchacha20(&sock->crypto, data, size, r);

	int a = htonl(r);

	char p[sizeof(int) + size];
	memcpy(p, &a, sizeof(int));
	memcpy(sizeof(int) + p, data, size);


	int w = sendto(sock->fd, p, sizeof(int) + size, 0, (struct sockaddr*)&sa, sizeof(sa));
	chipvpn_socket_set_write(sock, false);

	return w - sizeof(int);
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}