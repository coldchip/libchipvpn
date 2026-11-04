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
	if(!chipvpn_socket_init(&ipc->socket, fd)) {
		return false;
	}

	return true;
}

bool chipvpn_ipc_printf(chipvpn_ipc_t *ipc, const char* format, ...) {
	char buffer[1024];

	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	strcat(buffer, "\n");

	return chipvpn_socket_write(&ipc->socket, buffer, strlen(buffer), NULL) == strlen(buffer);
}

void chipvpn_ipc_cleanup(chipvpn_ipc_t *ipc) {
	chipvpn_socket_cleanup(&ipc->socket);
}