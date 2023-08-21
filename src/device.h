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
#include "socket.h"
#include "address.h"
#include "list.h"
#ifdef _WIN32
    #include <winsock2.h>
    #include <iptypes.h>
	#define IFNAMSIZ 256 
#else
    #include <netinet/in.h>
    #include <net/if.h>
#endif

typedef struct {
	int fd;
	char dev[IFNAMSIZ];
    int mtu;
	#ifdef _WIN32
	HANDLE tun_fd;
	HANDLE reader_thread;
	HANDLE writer_thread;
	chipvpn_address_t frontend_addr;
	chipvpn_address_t backend_addr;
	chipvpn_socket_t *frontend;
	chipvpn_socket_t *backend;
	#endif

    chipvpn_list_t peers;
} chipvpn_device_t;

chipvpn_device_t       *chipvpn_device_create();
#ifdef _WIN32
char                   *chipvpn_device_regquery(char *key_name);
IP_ADAPTER_INFO        *chipvpn_get_adapter_list();
IP_ADAPTER_INFO        *chipvpn_get_adapter(IP_ADAPTER_INFO *ai, char *guid);
#endif

bool                    chipvpn_device_set_name(chipvpn_device_t *device, const char* name);
bool                    chipvpn_device_set_address(chipvpn_device_t *tun, const char *address, uint8_t prefix);
bool                    chipvpn_device_set_mtu(chipvpn_device_t *tun, int mtu);
bool                    chipvpn_device_set_enabled(chipvpn_device_t *tun);
bool                    chipvpn_device_set_disabled(chipvpn_device_t *tun);
#ifdef _WIN32
DWORD WINAPI            chipvpn_device_reader(LPVOID arg);
DWORD WINAPI            chipvpn_device_writer(LPVOID arg);
#endif
int                     chipvpn_device_read(chipvpn_device_t *tun, void *buf, int size);
int                     chipvpn_device_write(chipvpn_device_t *tun, void *buf, int size);
void                    chipvpn_device_free(chipvpn_device_t *tun);

#ifdef __cplusplus
}
#endif

#endif