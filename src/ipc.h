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

#ifndef IPC_H
#define IPC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "address.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include <netinet/in.h>

typedef struct {
    int fd;
    int can_read;
    int can_write;
} chipvpn_ipc_t;

chipvpn_ipc_t          *chipvpn_ipc_create(const char *path);
void                    chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset);
void                    chipvpn_ipc_set_read(chipvpn_ipc_t *ipc, bool status);
void                    chipvpn_ipc_set_write(chipvpn_ipc_t *ipc, bool status);
bool                    chipvpn_ipc_can_read(chipvpn_ipc_t *ipc);
bool                    chipvpn_ipc_can_write(chipvpn_ipc_t *ipc);
int                     chipvpn_ipc_read(chipvpn_ipc_t *ipc, void *buf, int size, chipvpn_address_t *addr);
int                     chipvpn_ipc_write(chipvpn_ipc_t *ipc, void *buf, int size, chipvpn_address_t *addr);
void                    chipvpn_ipc_free(chipvpn_ipc_t *ipc);

#ifdef __cplusplus
}
#endif

#endif