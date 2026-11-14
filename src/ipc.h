#ifndef IPC_H
#define IPC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include "queue.h"

typedef struct {
	int fd;
	chipvpn_queue_t tx_queue;
	chipvpn_queue_t rx_queue;
} chipvpn_ipc_t;

bool                    chipvpn_ipc_init(chipvpn_ipc_t *ipc, int fd);
bool                    chipvpn_ipc_printf(chipvpn_ipc_t *ipc, const char* format, ...);

void                    chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset);

void                    chipvpn_ipc_cleanup(chipvpn_ipc_t *ipc);

#ifdef __cplusplus
}
#endif

#endif