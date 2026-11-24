#include "ipc.h"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include "chipvpn.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/un.h>
#include "queue.h"
#include "base64.h"

bool chipvpn_ipc_init(chipvpn_ipc_t *ipc, int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if(flags == -1) {
		return false;
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}

	ipc->fd = fd;

	if(!chipvpn_queue_init(&ipc->tx_queue, 4)) {
		return false;
	}

	if(!chipvpn_queue_init(&ipc->rx_queue, 4)) {
		chipvpn_queue_cleanup(&ipc->tx_queue);
		return false;
	}

	return true;
}

bool chipvpn_ipc_printf(chipvpn_ipc_t *ipc, const char* format, ...) {
	if(!chipvpn_queue_push_acquire(&ipc->tx_queue)) {
		return false;
	}

	char buffer[1024];

	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	strcat(buffer, "\n");

	return chipvpn_queue_push(&ipc->tx_queue, buffer, strlen(buffer), NULL) == strlen(buffer);
}

bool chipvpn_ipc_send_auth(chipvpn_ipc_t *ipc, const uint8_t *static_public, chipvpn_address_t *address, chipvpn_packet_auth_t *packet) {
	if(!chipvpn_queue_push_acquire(&ipc->tx_queue)) {
		return false;
	}

	chipvpn_auth_replay_t replay = {0};
	replay.address   = *address;
	replay.packet    = *packet;

	char pub_b64[64]     = {0};
	char replay_b64[280] = {0}; /* 191 bytes -> 256 b64 chars + NUL */

	b64_encode(static_public, CURVE25519_KEY_SIZE, (uint8_t*)pub_b64);
	b64_encode((const uint8_t*)&replay, sizeof(replay), (uint8_t*)replay_b64);

	printf("AUTH %s %s\n", pub_b64, replay_b64);

	/* chipvpn_ipc_printf appends '\n' automatically; total line is ~307 bytes */
	return chipvpn_ipc_printf(ipc, "AUTH %s %s\n", pub_b64, replay_b64);
}

void chipvpn_ipc_preselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_queue_push_acquire(&ipc->rx_queue)) FD_SET(ipc->fd, rdset); else FD_CLR(ipc->fd, rdset);
	if(chipvpn_queue_pop_acquire(&ipc->tx_queue))  FD_SET(ipc->fd, wdset); else FD_CLR(ipc->fd, wdset);
	*max = ipc->fd;
}

void chipvpn_ipc_postselect(chipvpn_ipc_t *ipc, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(ipc->fd, rdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_push_acquire(&ipc->rx_queue);
		if(entry) {
			ssize_t r = read(ipc->fd, entry->buffer, sizeof(entry->buffer));
			if(r > 0) {
				entry->size = (uint16_t)r;
				chipvpn_queue_push_commit(&ipc->rx_queue, entry);
			}
		}
	}

	if(FD_ISSET(ipc->fd, wdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_pop_acquire(&ipc->tx_queue);
		if(entry) {
			ssize_t w = write(ipc->fd, entry->buffer, entry->size);
			if(w > 0) {
				entry->size = (uint16_t)0u;
				chipvpn_queue_pop_commit(&ipc->tx_queue, entry);
			}
		}
	}
}

void chipvpn_ipc_cleanup(chipvpn_ipc_t *ipc) {
	chipvpn_queue_cleanup(&ipc->tx_queue);
	chipvpn_queue_cleanup(&ipc->rx_queue);
}