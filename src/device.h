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
#include "socket.h"
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

typedef enum {
    COMMAND_DEVICE_SECTION,
    COMMAND_PEER_SECTION
} chipvpn_command_section_e;

typedef struct {
    chipvpn_list_node_t node;
	int fd;
	char dev[IF_NAMESIZE + 1];
    chipvpn_list_t peers;
    chipvpn_socket_t *socket;
} chipvpn_device_t;

chipvpn_device_t       *chipvpn_device_create(int tun_fd);
bool                    chipvpn_device_set_name(chipvpn_device_t *device, const char *name);
bool                    chipvpn_device_set_address(chipvpn_device_t *device, chipvpn_address_t *network);
bool                    chipvpn_device_set_mtu(chipvpn_device_t *device, int mtu);
bool                    chipvpn_device_set_enabled(chipvpn_device_t *device);
bool                    chipvpn_device_set_disabled(chipvpn_device_t *device);
void                    chipvpn_device_free(chipvpn_device_t *device);

#ifdef __cplusplus
}
#endif

#endif