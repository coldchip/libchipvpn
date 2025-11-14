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


chipvpn_ipc_t *chipvpn_ipc_create(int rfd, int wfd) {
	chipvpn_ipc_t *ipc = malloc(sizeof(chipvpn_ipc_t));
	if(!ipc) {
		return NULL;
	}

	ipc->rfd = rfd;
	ipc->wfd = wfd;

	ipc->can_read  = 0;
	ipc->can_write = 0;

	return ipc;
}

void chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max) {
	if(ipc->can_read)  FD_CLR(ipc->rfd, rdset); else FD_SET(ipc->rfd, rdset);
	if(ipc->can_write) FD_CLR(ipc->wfd, wdset); else FD_SET(ipc->wfd, wdset);
	*max = MAX(ipc->rfd, ipc->wfd);
}

void chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(ipc->rfd, rdset)) ipc->can_read  = 1;
	if(FD_ISSET(ipc->wfd, wdset)) ipc->can_write = 1;
}

int chipvpn_ipc_can_read(chipvpn_ipc_t *ipc) {
	return ipc->can_read;
}

int chipvpn_ipc_can_write(chipvpn_ipc_t *ipc) {
	return ipc->can_write;
}

int chipvpn_ipc_read(chipvpn_ipc_t *ipc, void *buf, int size) {
	ipc->can_read = 0;
	return read(ipc->rfd, buf, size);
}

int chipvpn_ipc_write(chipvpn_ipc_t *ipc, void *buf, int size) {
	ipc->can_write = 0;
	return write(ipc->wfd, buf, size);
}

void chipvpn_ipc_free(chipvpn_ipc_t *ipc) {
	free(ipc);
}