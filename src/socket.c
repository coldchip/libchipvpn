#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include "socket.h"
#include <sys/socket.h>
#include <arpa/inet.h>

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

int chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr) {
	struct sockaddr_in sa;
	int len = sizeof(sa);

	int r = recvfrom(sock->fd, data, size, 0, (struct sockaddr*)&sa, (socklen_t*)&len);
	
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

	int w = sendto(sock->fd, data, size, 0, (struct sockaddr*)&sa, sizeof(sa));
	return w;
}

void chipvpn_socket_free(chipvpn_socket_t *sock) {
	close(sock->fd);
	free(sock);
}