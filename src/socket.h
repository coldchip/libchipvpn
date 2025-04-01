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

#define SOCKET_QUEUE_SIZE 128
#define SOCKET_QUEUE_ENTRY_SIZE 64000
#define SOCKET_FRAGMENT_ENTRY_SIZE 32

typedef struct __attribute__((__packed__)) {
	chipvpn_list_node_t node;
	uint16_t id;
	uint16_t size;
	uint16_t count;
	uint16_t offset;
	chipvpn_address_t addr;
	char buffer[SOCKET_FRAGMENT_ENTRY_SIZE];
} chipvpn_socket_fragment_entry_t;

typedef struct {
	chipvpn_list_node_t node;
	uint16_t id;
	bool is_used;
	int size;
	uint16_t count;
	chipvpn_address_t addr;
	chipvpn_list_t fragment;
} chipvpn_socket_queue_entry_t;

typedef struct {
	chipvpn_socket_queue_entry_t pool[SOCKET_QUEUE_SIZE];
	chipvpn_list_t queue;
} chipvpn_socket_queue_t;

typedef struct {
	int fd;
	chipvpn_socket_queue_t tx_queue;
	chipvpn_socket_queue_t rx_queue;
	chipvpn_address_t addr;
} chipvpn_socket_t;

chipvpn_socket_t                *chipvpn_socket_create();
bool                             chipvpn_socket_set_sendbuf(chipvpn_socket_t *sock, int size);
bool                             chipvpn_socket_set_recvbuf(chipvpn_socket_t *sock, int size);
bool                             chipvpn_socket_bind(chipvpn_socket_t *sock, chipvpn_address_t *bind);
void                             chipvpn_socket_preselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset, int *max);
void                             chipvpn_socket_postselect(chipvpn_socket_t *socket, fd_set *rdset, fd_set *wdset);

void                             chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue);
int                              chipvpn_socket_queue_size(chipvpn_socket_queue_t *queue);

chipvpn_socket_queue_entry_t    *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue, uint16_t id);
chipvpn_socket_queue_entry_t    *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue);

chipvpn_socket_fragment_entry_t *chipvpn_socket_dequeue_as_fragment(chipvpn_socket_queue_t *queue);


chipvpn_socket_queue_entry_t    *chipvpn_socket_available_entry(chipvpn_socket_queue_t *queue);

bool                             chipvpn_socket_can_enqueue(chipvpn_socket_t *socket);
bool                             chipvpn_socket_can_dequeue(chipvpn_socket_t *socket);
bool                             chipvpn_socket_can_read(chipvpn_socket_t *socket);
bool                             chipvpn_socket_can_write(chipvpn_socket_t *socket);

int                              chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
int                              chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
void                             chipvpn_socket_free(chipvpn_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif