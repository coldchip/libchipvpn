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

chipvpn_ipc_t *chipvpn_ipc_create(int fd) {
	chipvpn_ipc_t *ipc = malloc(sizeof(chipvpn_ipc_t));
	if(!ipc) {
		return NULL;
	}

	chipvpn_socket_t *sock = chipvpn_socket_create(fd);
	if(!sock) {
		return NULL;
	}

	ipc->socket = sock;

	return ipc;
}

bool chipvpn_ipc_printf(chipvpn_ipc_t *ipc, const char* format, ...) {
	char buffer[1024];

	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	strcat(buffer, "\n");

	return chipvpn_socket_write(ipc->socket, buffer, strlen(buffer), NULL) == strlen(buffer);
}

void chipvpn_ipc_free(chipvpn_ipc_t *ipc) {
	chipvpn_socket_free(ipc->socket);
	free(ipc);
}