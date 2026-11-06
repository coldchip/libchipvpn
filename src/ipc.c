#include "ipc.h"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "chipvpn.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/un.h>

bool chipvpn_ipc_init(chipvpn_ipc_t *ipc, int fd) {
	ipc->fd = fd;

	chipvpn_queue_init(&ipc->tx_queue, 4);
	chipvpn_queue_init(&ipc->rx_queue, 4);

	return true;
}

bool chipvpn_ipc_printf(chipvpn_ipc_t *ipc, const char* format, ...) {
	char buffer[1024];

	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	strcat(buffer, "\n");

	return chipvpn_queue_write(&ipc->tx_queue, buffer, strlen(buffer), NULL) == strlen(buffer);
}

void chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_queue_can_enqueue(&ipc->rx_queue)) FD_SET(ipc->fd, rdset); else FD_CLR(ipc->fd, rdset);
	if(chipvpn_queue_can_dequeue(&ipc->tx_queue)) FD_SET(ipc->fd, wdset); else FD_CLR(ipc->fd, wdset);
	*max = ipc->fd;
}

void chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(ipc->fd, rdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_enqueue_acquire(&ipc->rx_queue);
		if(!entry) {
			return;
		}

		ssize_t r = read(ipc->fd, entry->buffer, sizeof(entry->buffer));

		entry->size = r;

		chipvpn_queue_enqueue_commit(&ipc->rx_queue, entry);
	}
	if(FD_ISSET(ipc->fd, wdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_dequeue_acquire(&ipc->tx_queue);
		if(!entry) {
			return;
		}

		ssize_t w = write(ipc->fd, entry->buffer, entry->size);

		chipvpn_queue_dequeue_commit(&ipc->tx_queue, entry);
	}
}

void chipvpn_ipc_cleanup(chipvpn_ipc_t *ipc) {
	chipvpn_queue_cleanup(&ipc->tx_queue);
	chipvpn_queue_cleanup(&ipc->rx_queue);
}