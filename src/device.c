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

#include "device.h"
#include "socket.h"
#include "peer.h"
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "address.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>


chipvpn_device_t *chipvpn_device_create(int tun_fd) {
	chipvpn_device_t *device = malloc(sizeof(chipvpn_device_t));
	if(!device) {
		return NULL;
	}

	if(tun_fd < 0) {
		int fd = open("/dev/net/tun", O_RDWR);
		if(fd < 0) {
			return NULL;
		}

		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

		if(ioctl(fd, TUNSETIFF, &ifr) < 0) {
			close(fd);
			return NULL;
		}

		strcpy(device->dev, ifr.ifr_name);
		device->fd = fd;
	} else {
		device->fd = tun_fd;
	}

	device->can_read = 0;
	device->can_write = 0;

	chipvpn_list_clear(&device->peers);

	return device;
}

bool chipvpn_device_set_name(chipvpn_device_t *device, const char *name) {
	bool success = false;

	struct ifreq ifr;

	strcpy(ifr.ifr_name, device->dev);
	strcpy(ifr.ifr_newname, name);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if(ioctl(fd, SIOCSIFNAME, &ifr) != -1) {
		strcpy(device->dev, name);
		success = true;
	}

	close(fd);

	return success;
}

bool chipvpn_device_set_address(chipvpn_device_t *device, chipvpn_address_t *network) {
	bool success = true;

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, device->dev);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	addr->sin_addr.s_addr = network->ip;

	if(ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
		success = false;
	}

	if(network->prefix == 0) {
		addr->sin_addr.s_addr = 0;
	} else {
		addr->sin_addr.s_addr = htonl((0xFFFFFFFFUL << (32 - network->prefix)) & 0xFFFFFFFFUL);
	}

	if(ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
		success = false;
	}

	close(fd);

	return success;
}

bool chipvpn_device_set_mtu(chipvpn_device_t *device, int mtu) {
	bool success = true;

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, device->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_mtu = mtu;

	if(ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
		success = false;
	}

	close(fd);

	return success;
}

bool chipvpn_device_set_enabled(chipvpn_device_t *device) {
	bool success = true;

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, device->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_flags |= IFF_UP;

	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
		success = false;
	}

	close(fd);

	return success;
}

bool chipvpn_device_set_disabled(chipvpn_device_t *device) {
	bool success = true;

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, device->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_flags &= ~IFF_UP;

	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
		success = false;
	}

	close(fd);

	return success;
}

void chipvpn_device_preselect(chipvpn_device_t *device, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_device_can_read(device))  FD_CLR(device->fd, rdset); else FD_SET(device->fd, rdset);
	if(chipvpn_device_can_write(device)) FD_CLR(device->fd, wdset); else FD_SET(device->fd, wdset);
	*max = device->fd;
}

void chipvpn_device_postselect(chipvpn_device_t *device, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(device->fd, rdset)) chipvpn_device_set_read(device, true);
	if(FD_ISSET(device->fd, wdset)) chipvpn_device_set_write(device, true);
}

void chipvpn_device_set_read(chipvpn_device_t *device, bool status) {
	device->can_read = status;
}

void chipvpn_device_set_write(chipvpn_device_t *device, bool status) {
	device->can_write = status;
}

bool chipvpn_device_can_read(chipvpn_device_t *device) {
	return device->can_read;
}

bool chipvpn_device_can_write(chipvpn_device_t *device) {
	return device->can_write;
}

int chipvpn_device_read(chipvpn_device_t *device, void *buf, int size) {
	int r = read(device->fd, buf, size);
	chipvpn_device_set_read(device, false);
	return r;
}

int chipvpn_device_write(chipvpn_device_t *device, void *buf, int size) {
	int w = write(device->fd, buf, size);
	chipvpn_device_set_write(device, false);
	return w;
}

void chipvpn_device_free(chipvpn_device_t *device) {
	close(device->fd);

	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_peer_free(peer);
	}

	free(device);
}