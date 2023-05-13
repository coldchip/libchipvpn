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

#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stdbool.h>
#include "address.h"
#include "chipvpn.h"
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <netinet/in.h>
    #include <net/if.h>
#endif

typedef struct {
    #ifdef _WIN32
    HANDLE tun_fd;
    char dev[128];
    #else
	char dev[IFNAMSIZ];
    #endif
	int fd;
} chipvpn_tun_t;

chipvpn_tun_t          *chipvpn_tun_create(const char *dev);
char                   *chipvpn_tun_regquery(char *key_name);
void                    get_name(char *ifname, int namelen, char *dev_name);
bool                    chipvpn_tun_setip(chipvpn_tun_t *tun, chipvpn_address_t *addr, int mtu, int qlen);
bool                    chipvpn_tun_ifup(chipvpn_tun_t *tun);
DWORD WINAPI            chipvpn_tun_reader(LPVOID arg);
DWORD WINAPI            chipvpn_tun_writer(LPVOID arg);
int                     chipvpn_tun_read(chipvpn_tun_t *tun, void *buf, int size);
int                     chipvpn_tun_write(chipvpn_tun_t *tun, void *buf, int size);
void                    chipvpn_tun_free(chipvpn_tun_t *tun);

#endif