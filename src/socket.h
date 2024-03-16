#ifndef SOCKET_H
#define SOCKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/select.h>
#include "address.h"
#include "crypto.h"

typedef struct {
	int fd;
	int can_read;
	int can_write;
	char key[1024];
	int key_length;
	chipvpn_crypto_t crypto;
} chipvpn_socket_t;

chipvpn_socket_t    *chipvpn_socket_create();
bool                 chipvpn_socket_bind(chipvpn_socket_t *sock, chipvpn_address_t *bind);
void                 chipvpn_socket_set_key(chipvpn_socket_t *sock, const char *key, int length);
void                 chipvpn_socket_preselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset, int *max);
void                 chipvpn_socket_postselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset);
void                 chipvpn_socket_set_read(chipvpn_socket_t *sock, bool status);
void                 chipvpn_socket_set_write(chipvpn_socket_t *sock, bool status);
bool                 chipvpn_socket_can_read(chipvpn_socket_t *sock);
bool                 chipvpn_socket_can_write(chipvpn_socket_t *sock);
int                  chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
int                  chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
void                 chipvpn_socket_free(chipvpn_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif