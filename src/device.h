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

#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include "address.h"
#include "list.h"
#include <netinet/in.h>
#include <net/if.h>

#ifdef __linux__
#define IFF_TUN 0x0001
#define IFF_NO_PI 0x1000
#define TUNSETIFF _IOW('T', 202, int)
#define TUNSETPERSIST _IOW('T', 203, int)
#endif

typedef struct {
	int fd;
    int can_read;
    int can_write;
	char dev[IFNAMSIZ + 1];
    chipvpn_list_t peers;
} chipvpn_device_t;

chipvpn_device_t       *chipvpn_device_create(int tun_fd);
bool                    chipvpn_device_set_name(chipvpn_device_t *device, const char *name);
bool                    chipvpn_device_set_address(chipvpn_device_t *device, chipvpn_address_t *network);
bool                    chipvpn_device_set_mtu(chipvpn_device_t *tun, int mtu);
bool                    chipvpn_device_set_enabled(chipvpn_device_t *tun);
bool                    chipvpn_device_set_disabled(chipvpn_device_t *tun);
void                    chipvpn_device_preselect(chipvpn_device_t *device, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_device_postselect(chipvpn_device_t *device, fd_set *rdset, fd_set *wdset);
void                    chipvpn_device_set_read(chipvpn_device_t *device, bool status);
void                    chipvpn_device_set_write(chipvpn_device_t *device, bool status);
bool                    chipvpn_device_can_read(chipvpn_device_t *device);
bool                    chipvpn_device_can_write(chipvpn_device_t *device);
int                     chipvpn_device_read(chipvpn_device_t *tun, void *buf, int size);
int                     chipvpn_device_write(chipvpn_device_t *tun, void *buf, int size);
void                    chipvpn_device_free(chipvpn_device_t *tun);

#ifdef __cplusplus
}
#endif

#endif