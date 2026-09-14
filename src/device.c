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
#include "util.h"
#include "hmac_sha256.h"
#include "base64.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

/*
 * Perform an ioctl on a freshly opened AF_INET datagram socket.
 * The interface name is pre-filled into ifr. Returns true on success.
 * Centralises the boilerplate shared by every device setter below.
 */
static bool chipvpn_device_ioctl(chipvpn_device_t *device, unsigned long request, struct ifreq *ifr) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		return false;
	}

	bool success = ioctl(fd, request, ifr) != -1;

	close(fd);

	return success;
}

chipvpn_device_t *chipvpn_device_create(int fd) {
	chipvpn_device_t *device = malloc(sizeof(chipvpn_device_t));
	if(!device) {
		return NULL;
	}

	if(fd < 0) {
		fd = open("/dev/net/tun", O_RDWR);
		if(fd < 0) {
			free(device);
			return NULL;
		}

		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

		if(ioctl(fd, TUNSETIFF, &ifr) < 0) {
			close(fd);
			free(device);
			return NULL;
		}

		strcpy(device->dev, ifr.ifr_name);
	}

	chipvpn_socket_t *sock = chipvpn_socket_create(fd, CHIPVPN_SOCKET_STREAM);
	if(!sock) {
		close(fd);
		free(device);
		return NULL;
	}

	device->fd     = fd;
	device->socket = sock;

	chipvpn_list_clear(&device->peers);

	return device;
}

bool chipvpn_device_set_name(chipvpn_device_t *device, const char *name) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device->dev);
	strcpy(ifr.ifr_newname, name);

	if(!chipvpn_device_ioctl(device, SIOCSIFNAME, &ifr)) {
		return false;
	}

	strcpy(device->dev, name);
	return true;
}

bool chipvpn_device_set_address(chipvpn_device_t *device, chipvpn_address_t *network) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, device->dev);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

	bool success = true;

	addr->sin_addr.s_addr = network->ip;
	if(!chipvpn_device_ioctl(device, SIOCSIFADDR, &ifr)) {
		success = false;
	}

	if(network->prefix == 0) {
		addr->sin_addr.s_addr = 0;
	} else {
		addr->sin_addr.s_addr = htonl((0xFFFFFFFFUL << (32 - network->prefix)) & 0xFFFFFFFFUL);
	}

	if(!chipvpn_device_ioctl(device, SIOCSIFNETMASK, &ifr)) {
		success = false;
	}

	return success;
}

bool chipvpn_device_set_mtu(chipvpn_device_t *device, int mtu) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, device->dev);

	ifr.ifr_mtu = mtu;

	return chipvpn_device_ioctl(device, SIOCSIFMTU, &ifr);
}

bool chipvpn_device_set_enabled(chipvpn_device_t *device) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, device->dev);

	ifr.ifr_flags |= IFF_UP;

	return chipvpn_device_ioctl(device, SIOCSIFFLAGS, &ifr);
}

bool chipvpn_device_set_disabled(chipvpn_device_t *device) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, device->dev);

	ifr.ifr_flags &= ~IFF_UP;

	return chipvpn_device_ioctl(device, SIOCSIFFLAGS, &ifr);
}

bool chipvpn_device_set_public_key(chipvpn_device_t *device, const char *key) {
	return b64_decode((uint8_t*)key, strlen(key), device->public) > 0;
}

bool chipvpn_device_set_private_key(chipvpn_device_t *device, const char *key) {
	return b64_decode((uint8_t*)key, strlen(key), device->private) > 0;
}

void chipvpn_device_free(chipvpn_device_t *device) {
	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_peer_free(peer);
	}

	chipvpn_socket_free(device->socket);

	close(device->fd);

	free(device);
}
