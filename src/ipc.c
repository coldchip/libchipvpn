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

#include "ipc.h"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/un.h>


chipvpn_ipc_t *chipvpn_ipc_create(const char *path) {
	chipvpn_ipc_t *ipc = malloc(sizeof(chipvpn_ipc_t));
	if(!ipc) {
		return NULL;
	}

	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(fd == -1) {
		return NULL;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path);

    if(bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
    	return NULL;
    }

	ipc->fd = fd;

	ipc->can_read = 0;
	ipc->can_write = 0;

	return ipc;
}

void chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_ipc_can_read(ipc))  FD_CLR(ipc->fd, rdset); else FD_SET(ipc->fd, rdset);
	if(chipvpn_ipc_can_write(ipc)) FD_CLR(ipc->fd, wdset); else FD_SET(ipc->fd, wdset);
	*max = MAX(ipc->fd, ipc->fd);
}

void chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(ipc->fd, rdset)) chipvpn_ipc_set_read(ipc, true);
	if(FD_ISSET(ipc->fd, wdset)) chipvpn_ipc_set_write(ipc, true);
}

void chipvpn_ipc_set_read(chipvpn_ipc_t *ipc, bool status) {
	ipc->can_read = status;
}

void chipvpn_ipc_set_write(chipvpn_ipc_t *ipc, bool status) {
	ipc->can_write = status;
}

bool chipvpn_ipc_can_read(chipvpn_ipc_t *ipc) {
	return ipc->can_read;
}

bool chipvpn_ipc_can_write(chipvpn_ipc_t *ipc) {
	return ipc->can_write;
}

int chipvpn_ipc_read(chipvpn_ipc_t *ipc, void *buf, int size, chipvpn_address_t *addr) {
	struct sockaddr_un client;
	socklen_t len = sizeof(client);

	int r = recvfrom(ipc->fd, buf, size, 0, (struct sockaddr*)&client, &len);
	chipvpn_ipc_set_read(ipc, false);

	memcpy(addr->path, client.sun_path, sizeof(addr->path));

	return r;
}

int chipvpn_ipc_write(chipvpn_ipc_t *ipc, void *buf, int size, chipvpn_address_t *addr) {
	struct sockaddr_un client;
	memset(&client, 0, sizeof(struct sockaddr_un));
    client.sun_family = AF_UNIX;
	memcpy(client.sun_path, addr->path, sizeof(addr->path));

	int w = sendto(ipc->fd, buf, size, 0, (struct sockaddr*)&client, sizeof(client));
	chipvpn_ipc_set_write(ipc, false);
	return w;
}

void chipvpn_ipc_free(chipvpn_ipc_t *ipc) {
	close(ipc->fd);
	free(ipc);
}