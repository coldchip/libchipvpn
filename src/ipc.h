#ifndef IPC_H
#define IPC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include "socket.h"

typedef struct {
    chipvpn_socket_t socket;
} chipvpn_ipc_t;

bool                    chipvpn_ipc_init(chipvpn_ipc_t *ipc, int fd);
bool                    chipvpn_ipc_printf(chipvpn_ipc_t *ipc, const char* format, ...);
void                    chipvpn_ipc_cleanup(chipvpn_ipc_t *ipc);

#ifdef __cplusplus
}
#endif

#endif