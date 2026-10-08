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

#ifndef UDP_H
#define UDP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include "socket.h"

typedef struct {
    int fd;
    chipvpn_socket_t *socket;
} chipvpn_udp_t;

chipvpn_udp_t          *chipvpn_udp_create(int fd);
void                    chipvpn_udp_tx_transform(void *transform_data, uint8_t *out, size_t *out_size, uint8_t *in, size_t in_size);
void                    chipvpn_udp_rx_transform(void *transform_data, uint8_t *out, size_t *out_size, uint8_t *in, size_t in_size);
bool                    chipvpn_udp_set_recvbuf(chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_sendbuf(chipvpn_udp_t *sock, int size);
bool                    chipvpn_udp_set_fwmark(chipvpn_udp_t *sock, int fwmark);
bool                    chipvpn_udp_bind(chipvpn_udp_t *sock, chipvpn_address_t *bind);
void                    chipvpn_udp_free(chipvpn_udp_t *ipc);

#ifdef __cplusplus
}
#endif

#endif