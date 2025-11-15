/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@chip.sg>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

#include "udp.h"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/un.h>


chipvpn_udp_t *chipvpn_udp_create() {
	chipvpn_udp_t *ipc = malloc(sizeof(chipvpn_udp_t));
	if(!ipc) {
		return NULL;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		return NULL;
	}

	chipvpn_socket_t *sock = chipvpn_socket_create(fd, fd, CHIPVPN_SOCKET_DGRAM);
	if(!sock) {
		return NULL;
	}

	ipc->fd = fd;
	ipc->socket = sock;

	return ipc;
}

bool chipvpn_udp_set_recvbuf(chipvpn_udp_t *sock, int size) {
	if(setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
		return false;
	}
	return true;
}

bool chipvpn_udp_set_sendbuf(chipvpn_udp_t *sock, int size) {
	if(setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0) {
		return false;
	}
	return true;
}

bool chipvpn_udp_bind(chipvpn_udp_t *sock, chipvpn_address_t *addr) {
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

void chipvpn_udp_free(chipvpn_udp_t *ipc) {
	chipvpn_socket_free(ipc->socket);
	close(ipc->fd);
	free(ipc);
}