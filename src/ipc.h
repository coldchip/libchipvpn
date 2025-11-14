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

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>

typedef struct {
    int rfd;
    int wfd;
    int can_read;
    int can_write;
} chipvpn_ipc_t;

chipvpn_ipc_t          *chipvpn_ipc_create(int rfd, int wfd);
void                    chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset);
int                     chipvpn_ipc_can_read(chipvpn_ipc_t *ipc);
int                     chipvpn_ipc_can_write(chipvpn_ipc_t *ipc);
int                     chipvpn_ipc_read(chipvpn_ipc_t *ipc, void *buf, int size);
int                     chipvpn_ipc_write(chipvpn_ipc_t *ipc, void *buf, int size);
void                    chipvpn_ipc_free(chipvpn_ipc_t *ipc);

#ifdef __cplusplus
}
#endif

#endif