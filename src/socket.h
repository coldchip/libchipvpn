#ifndef SOCKET_H
#define SOCKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/select.h>
#include "address.h"
#include "list.h"

// Allocate about 1MB of buffer
#define SOCKET_QUEUE_SIZE 64
#define SOCKET_QUEUE_ENTRY_SIZE 16000

typedef enum {
	CHIPVPN_SOCKET_DGRAM = 0,
	CHIPVPN_SOCKET_STREAM = 1
} chipvpn_socket_type_e;

typedef struct {
	chipvpn_list_node_t node;
	bool is_used;
	int size;
	chipvpn_address_t addr;
	char buffer[SOCKET_QUEUE_ENTRY_SIZE];
} chipvpn_socket_queue_entry_t;

typedef struct {
	chipvpn_socket_queue_entry_t pool[SOCKET_QUEUE_SIZE];
	chipvpn_list_t queue;
	int size;
} chipvpn_socket_queue_t;

typedef struct {
	int rfd;
	int wfd;
	chipvpn_socket_queue_t tx_queue;
	chipvpn_socket_queue_t rx_queue;
	chipvpn_socket_type_e type;
} chipvpn_socket_t;

chipvpn_socket_t                *chipvpn_socket_create(int rfd, int wfd, int type);
void                             chipvpn_socket_preselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset, int *max);
void                             chipvpn_socket_postselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset);

void                             chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue);
int                              chipvpn_socket_queue_size(chipvpn_socket_queue_t *queue);

chipvpn_socket_queue_entry_t    *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue);
chipvpn_socket_queue_entry_t    *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue);
void                             chipvpn_socket_enqueue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry);
void                             chipvpn_socket_dequeue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry);

chipvpn_socket_queue_entry_t    *chipvpn_socket_available_entry(chipvpn_socket_queue_t *queue);

bool                             chipvpn_socket_can_enqueue(chipvpn_socket_t *sock);
bool                             chipvpn_socket_can_dequeue(chipvpn_socket_t *sock);
bool                             chipvpn_socket_can_read(chipvpn_socket_t *sock);
bool                             chipvpn_socket_can_write(chipvpn_socket_t *sock);

int                              chipvpn_socket_read(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
int                              chipvpn_socket_write(chipvpn_socket_t *sock, void *data, int size, chipvpn_address_t *addr);
void                             chipvpn_socket_free(chipvpn_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif