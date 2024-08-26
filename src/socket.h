#ifndef SOCKET_H
#define SOCKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/select.h>
#include "address.h"
#include "crypto.h"
#include "list.h"

typedef struct {
	chipvpn_list_node_t node;
	bool is_used;
	int size;
	chipvpn_address_t addr;
	char buffer[8192];
} chipvpn_socket_queue_t;

typedef struct {
	int fd;
	char key[1024];
	int key_length;
	uint32_t counter;
	chipvpn_socket_queue_t queue_pool[40];
	chipvpn_list_t tx_queue;
	chipvpn_list_t rx_queue;
	chipvpn_address_t addr;
} chipvpn_socket_t;

chipvpn_socket_t       *chipvpn_socket_create();
bool                    chipvpn_socket_set_sendbuf(chipvpn_socket_t *sock, int size);
bool                    chipvpn_socket_set_recvbuf(chipvpn_socket_t *sock, int size);
bool                    chipvpn_socket_bind(chipvpn_socket_t *sock, chipvpn_address_t *bind);
void                    chipvpn_socket_set_key(chipvpn_socket_t *sock, const char *key, int length);
void                    chipvpn_socket_preselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset, int *max);
void                    chipvpn_socket_postselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset);
void                    chipvpn_socket_reset_queue(chipvpn_socket_t *sock);
chipvpn_socket_queue_t *chipvpn_socket_acquire_queue(chipvpn_socket_t *sock);
void                    chipvpn_socket_release_queue(chipvpn_socket_queue_t *queue);
bool                    chipvpn_socket_can_enqueue(chipvpn_socket_t *sock);
bool                    chipvpn_socket_can_dequeue(chipvpn_socket_t *sock);
bool                    chipvpn_socket_can_read(chipvpn_socket_t *sock);
bool                    chipvpn_socket_can_write(chipvpn_socket_t *sock);
int                     chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
int                     chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
void                    chipvpn_socket_free(chipvpn_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif